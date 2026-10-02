#include "BatteryMonitor.h"

#include <Arduino.h>
#include <BoardConfig.h>
#include <M5Pm1.h>
#include <esp_idf_version.h>
#if ESP_IDF_VERSION_MAJOR < 5
#include <esp_adc_cal.h>
#endif
#if defined(ENABLE_SERIAL_LOG)
#include <esp_rom_sys.h>
#endif

#include <algorithm>
#include <cmath>

#if FREEINK_BATTERY_I2C_GAUGE
#include <Wire.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#if FREEINK_DEVICE_WS397
#include <Axp2101.h>
#endif

// Minimal, dependency-free I2C fuel-gauge read for boards that carry one (e.g.
// LilyGo T5 S3: BQ27220 gauge + BQ25896 charger). Standard TI command registers;
// the gauge reports true battery state, so no ADC pin or divider is involved.
// Addresses/pins come from BoardConfig::ACTIVE.batteryGauge.
namespace {
constexpr uint8_t BQ27220_VOLTAGE = 0x08;          // battery voltage, mV (u16 LE)
constexpr uint8_t BQ27220_CURRENT = 0x0C;          // average current, signed mA (i16 LE)
constexpr uint8_t BQ27220_STATE_OF_CHARGE = 0x2C;  // SoC, percent (u16 LE)
constexpr uint8_t BQ25896_REG_STATUS = 0x0B;       // CHRG_STAT in bits [4:3]

// The gauge's I2C controller (Wire or Wire1) per BoardConfig. On single-bus SoCs
// (ESP32-C3, SOC_I2C_NUM == 1) Wire1 doesn't exist, so always use Wire there.
TwoWire& gaugeWire() {
#if SOC_I2C_NUM > 1
  if (BoardConfig::ACTIVE.batteryGauge.i2cBus == 1) return Wire1;
#endif
  return Wire;
}

bool g_wireReady = false;
void ensureWire() {
  if (g_wireReady) return;
  const auto& g = BoardConfig::ACTIVE.batteryGauge;
  gaugeWire().begin(g.i2cSda, g.i2cScl, g.i2cHz);
  g_wireReady = true;
}

// gaugeWire() is one shared TwoWire bus (gauge + charger, and on some boards
// touch/RTC pins too), reached from at least two independent FreeRTOS tasks:
// the render task (this file's own multi-step BQ27220 provisioning, which can
// hold the bus for seconds) and the main loop task (HalGPIO::isUsbConnected()
// falls back to BatteryMonitor::isCharging() on boards with no dedicated
// usb-detect pin, e.g. LilyGo T5 S3, and main.cpp calls it every iteration).
// TwoWire/the underlying i2c_master driver isn't safe for concurrent use from
// two tasks -- same class of hazard as SdFat (see this project's storageMutex
// in HalStorage) -- and without serializing here, two transactions landing at
// once corrupt the driver's state machine (observed as sporadic
// ESP_ERR_INVALID_STATE from esp32-hal-i2c-ng, most visible during the long
// BQ27220 provisioning sequence below). Lazily created: C++11 guarantees a
// function-local static's initialization is itself thread-safe.
SemaphoreHandle_t i2cBusMutex() {
  static SemaphoreHandle_t mutex = xSemaphoreCreateMutex();
  return mutex;
}

struct I2cBusLock {
  I2cBusLock() { xSemaphoreTake(i2cBusMutex(), portMAX_DELAY); }
  ~I2cBusLock() { xSemaphoreGive(i2cBusMutex()); }
  I2cBusLock(const I2cBusLock&) = delete;
  I2cBusLock& operator=(const I2cBusLock&) = delete;
};

bool readReg16(uint8_t addr, uint8_t reg, uint16_t& out) {
  if (addr == 0) return false;
  I2cBusLock lock;
  ensureWire();
  TwoWire& w = gaugeWire();
  w.beginTransmission(addr);
  w.write(reg);
  if (w.endTransmission(false) != 0) return false;
  if (w.requestFrom(addr, static_cast<uint8_t>(2), static_cast<uint8_t>(true)) < 2) return false;
  const uint8_t lo = w.read();
  const uint8_t hi = w.read();
  out = static_cast<uint16_t>(lo) | (static_cast<uint16_t>(hi) << 8);
  return true;
}

bool readReg8(uint8_t addr, uint8_t reg, uint8_t& out) {
  if (addr == 0) return false;
  I2cBusLock lock;
  ensureWire();
  TwoWire& w = gaugeWire();
  w.beginTransmission(addr);
  w.write(reg);
  if (w.endTransmission(false) != 0) return false;
  if (w.requestFrom(addr, static_cast<uint8_t>(1), static_cast<uint8_t>(true)) < 1) return false;
  out = w.read();
  return true;
}

bool writeReg8(uint8_t addr, uint8_t reg, uint8_t val) {
  if (addr == 0) return false;
  I2cBusLock lock;
  ensureWire();
  TwoWire& w = gaugeWire();
  w.beginTransmission(addr);
  w.write(reg);
  w.write(val);
  return w.endTransmission(true) == 0;
}

// --- CW2017 (CellWise) fuel gauge -------------------------------------------
// Register map + init recovered from the Xteink X4 Pro OEM firmware (the
// XTEink::Cw2017PowerHal class in app1) via Ghidra. Unlike the BQ27220, the CW2017
// reports 0% until a matching 80-byte BATINFO battery profile is resident, so init
// must verify/upload one before SoC reads mean anything.
constexpr uint8_t CW2017_REG_VERSION = 0x00;    // 0xA0 while starting; running versions match 0x0D/0x0F
constexpr uint8_t CW2017_REG_VCELL_H = 0x02;    // 14-bit VCELL, big-endian over 0x02/0x03
constexpr uint8_t CW2017_REG_SOC = 0x04;        // integer percent
constexpr uint8_t CW2017_REG_SOC_FRAC = 0x05;   // 1/256 percent, the low byte of the same value
constexpr uint8_t CW2017_REG_MODE = 0x08;       // soft-reset / sleep control
constexpr uint8_t CW2017_REG_SOC_ALERT = 0x0B;  // bit7 = profile-loaded / update-enable
constexpr uint8_t CW2017_REG_BATINFO = 0x10;    // 80-byte profile spans 0x10..0x5F

constexpr uint8_t CW2017_MODE_NORMAL = 0x00;
constexpr uint8_t CW2017_MODE_RESTART = 0x30;
constexpr uint8_t CW2017_MODE_DEFAULT = 0xF0;
constexpr uint8_t CW2017_UPDATE_FLAG = 0x80;
constexpr unsigned long CW2017_INIT_RETRY_MS = 1000;

// The exact BATINFO profile the OEM uploads (app1 table @ DROM 0x3c5d8d00). This is
// battery-model-specific; it is the profile for the X4 Pro's cell.
constexpr uint8_t CW2017_BATINFO[80] = {
    0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbf, 0xb5, 0xb4, 0xa4, 0x9c, 0xeb, 0xe2,
    0xdf, 0xe5, 0xca, 0xa0, 0x8a, 0x62, 0x53, 0x48, 0x40, 0x3a, 0x32, 0xb1, 0xae, 0xda, 0xb5, 0xff,
    0xff, 0xff, 0xe8, 0xdb, 0xd9, 0xd6, 0xd4, 0xd2, 0xd0, 0xcb, 0xc3, 0xbc, 0x9e, 0x87, 0x7b, 0x71,
    0x72, 0x7c, 0x8c, 0xa3, 0xb7, 0xc8, 0xa5, 0x4f, 0x00, 0x00, 0xab, 0x02, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x23};

bool cw2017VersionIsRunning(const uint8_t version) { return (version & 0xFD) == 0x0D; }

// Soft-reset: MODE 0xF0 -> 0x30 -> 0x00, 20 ms apart (OEM FUN_4215042c).
bool cw2017Reset(const uint8_t addr) {
  if (!writeReg8(addr, CW2017_REG_MODE, CW2017_MODE_DEFAULT)) return false;
  delay(20);
  if (!writeReg8(addr, CW2017_REG_MODE, CW2017_MODE_RESTART)) return false;
  delay(20);
  if (!writeReg8(addr, CW2017_REG_MODE, CW2017_MODE_NORMAL)) return false;
  delay(20);
  return true;
}

// Wait for the calculation engine to leave its 0xA0 startup state, then for a
// valid SoC. The bounds mirror the vendor drivers: roughly 1 s for VERSION and
// 3 s for SoC, but this path only runs after a reset/profile update.
bool cw2017WaitUntilReady(const uint8_t addr) {
  bool versionReady = false;
  for (int i = 0; i < 50; ++i) {
    uint8_t version = 0;
    if (readReg8(addr, CW2017_REG_VERSION, version) && cw2017VersionIsRunning(version)) {
      versionReady = true;
      break;
    }
    delay(20);
  }
  if (!versionReady) return false;

  for (int i = 0; i < 30; ++i) {
    uint8_t soc = 0;
    if (readReg8(addr, CW2017_REG_SOC, soc) && soc <= 100) return true;
    delay(100);
  }
  return false;
}

// Check the update flag and compare every resident BATINFO byte. An I2C error is
// kept distinct from a real mismatch so a transient bus failure never triggers
// a partial profile rewrite.
bool cw2017ProfileMatches(const uint8_t addr, bool& matches) {
  uint8_t config = 0;
  if (!readReg8(addr, CW2017_REG_SOC_ALERT, config)) return false;
  if ((config & CW2017_UPDATE_FLAG) == 0) {
    matches = false;
    return true;
  }

  for (uint8_t i = 0; i < sizeof(CW2017_BATINFO); ++i) {
    uint8_t stored = 0;
    if (!readReg8(addr, static_cast<uint8_t>(CW2017_REG_BATINFO + i), stored)) return false;
    if (stored != CW2017_BATINFO[i]) {
      matches = false;
      return true;
    }
  }

  matches = true;
  return true;
}

// Make sure the gauge is running with the correct profile. Every failure is
// propagated so callers can retry instead of permanently accepting a failed
// first attempt. This matters on the X4 Pro because the gauge shares Wire with
// the GT911 and an early transient I2C error is otherwise easy to cache forever.
bool cw2017EnsureProfile(const uint8_t addr) {
  uint8_t mode = 0;
  uint8_t version = 0;
  if (!readReg8(addr, CW2017_REG_MODE, mode)) return false;
  if (!readReg8(addr, CW2017_REG_VERSION, version)) return false;

  bool profileMatches = false;
  if (!cw2017ProfileMatches(addr, profileMatches)) return false;

  bool restartRequired = mode != CW2017_MODE_NORMAL || !cw2017VersionIsRunning(version);
  if (!profileMatches) {
    for (uint8_t i = 0; i < sizeof(CW2017_BATINFO); ++i) {
      if (!writeReg8(addr, static_cast<uint8_t>(CW2017_REG_BATINFO + i), CW2017_BATINFO[i])) return false;
    }
    if (!writeReg8(addr, CW2017_REG_SOC_ALERT, CW2017_UPDATE_FLAG)) return false;
    delay(20);
    restartRequired = true;
  }

  if (restartRequired) {
    if (!cw2017Reset(addr)) return false;
    return cw2017WaitUntilReady(addr);
  }

  uint8_t soc = 0;
  if (!readReg8(addr, CW2017_REG_SOC, soc)) return false;
  if (soc <= 100) return true;

  // A running gauge should never expose an invalid integer SoC. Give it one
  // controlled restart rather than marking initialization successful forever.
  if (!cw2017Reset(addr)) return false;
  return cw2017WaitUntilReady(addr);
}

// --- BQ27220 (TI) fuel gauge data-memory provisioning -----------------------
// Diagnostics (serial log, same card) already confirmed: the BQ25896 charger
// is correctly configured (its registers exactly match LilyGo's own factory
// firmware values) and the gauge's raw voltage/current reads are accurate --
// VBAT settled near the charger's real target with 0mA current, i.e. a
// genuinely near-full pack -- while the gauge's own reported SoC sat around
// 35%. The gauge computes SoC from a CEDV (Compensated End-of-Discharge
// Voltage) model held in its non-volatile data memory, not from voltage
// alone, and firmware never wrote that configuration -- it only ever read
// BQ27220_VOLTAGE/CURRENT/STATE_OF_CHARGE above. That reconciles accurate
// voltage with an inaccurate percentage.
//
// The table below is LilyGo's own BQ27220 data-memory profile (their
// T5S3-4.7-e-paper-PRO repo, lib/BQ27220/bq27220_data_memory.c -- header
// comment there labels it for their T-Embed-CC1101 board; no T5S3-specific
// profile is published). FullChargeCapacity/DesignCapacity match this
// board's 1500mAh cell exactly; the EMF/impedance/DOD-curve constants are
// this chip family's reference values rather than ones characterized
// against this exact cell. This only ever changes what percentage gets
// reported: the gauge cannot influence charge voltage or current, which the
// BQ25896 controls independently and already reads back correct, so a wrong
// value here is a calibration gap, not a safety concern.
constexpr uint8_t BQ27220_CMD_CONTROL = 0x00;
constexpr uint8_t BQ27220_CMD_OPERATION_STATUS = 0x3A;
constexpr uint8_t BQ27220_CMD_SELECT_SUBCLASS = 0x3E;
constexpr uint8_t BQ27220_CMD_MAC_DATA = 0x40;
constexpr uint8_t BQ27220_CMD_MAC_DATA_SUM = 0x60;

constexpr uint16_t BQ27220_CONTROL_DEVICE_NUMBER = 0x0001;
constexpr uint16_t BQ27220_CONTROL_SEALED = 0x0030;
constexpr uint16_t BQ27220_CONTROL_RESET = 0x0041;
constexpr uint16_t BQ27220_CONTROL_ENTER_CFG_UPDATE = 0x0090;
constexpr uint16_t BQ27220_CONTROL_EXIT_CFG_UPDATE_REINIT = 0x0091;
constexpr uint16_t BQ27220_CONTROL_UNSEAL_KEY1 = 0x0414;
constexpr uint16_t BQ27220_CONTROL_UNSEAL_KEY2 = 0x3672;
constexpr uint16_t BQ27220_CONTROL_FULL_ACCESS_KEY = 0xFFFF;
constexpr uint16_t BQ27220_DEVICE_ID = 0x0220;

// OperationStatus (read directly from CommandOperationStatus).
constexpr uint16_t BQ27220_OPSTATUS_SEC_MASK = 0x0006;  // bits [2:1]
constexpr uint8_t BQ27220_OPSTATUS_SEC_SHIFT = 1;
constexpr uint8_t BQ27220_SEC_SEALED = 0b11;
constexpr uint8_t BQ27220_SEC_UNSEALED = 0b10;
constexpr uint8_t BQ27220_SEC_FULL = 0b01;
constexpr uint16_t BQ27220_OPSTATUS_INITCOMP = 1u << 7;
constexpr uint16_t BQ27220_OPSTATUS_CFGUPDATE = 1u << 10;
// ControlStatus (read directly from CommandControl) BATT_ID is bits [2:0].
constexpr uint16_t BQ27220_CTRLSTATUS_BATT_ID_MASK = 0x0007;

struct Bq27220DmEntry {
  uint16_t address;
  uint8_t size;  // 1 or 2 bytes
  uint32_t value;
};

// LilyGo's gauge_data_memory[] table, address-for-address and value-for-value.
// GaugingConfig is inlined as its resolved 16-bit value (0x0D31: low byte 0x31
// = CCT|SC|FIXED_EDV0, high byte 0x0D = FCC_LIM|FC_FOR_VDQ|IGNORE_SD) instead
// of the pointer-to-bitfield the vendor driver reads it through, so one plain
// table serves both the write and the read-back verify below.
constexpr Bq27220DmEntry BQ27220_DATA_MEMORY[] = {
    {0x9206, 2, 0x0C8C},  // OperationConfigA
    {0x9208, 1, 0x4C},    // OperationConfigB
    {0x929B, 2, 0x0D31},  // CEDV Profile 1 GaugingConfig
    {0x929D, 2, 1500},    // FullChargeCapacity (mAh)
    {0x929F, 2, 1500},    // DesignCapacity (mAh)
    {0x92A3, 2, 3743},    // EMF
    {0x92A9, 2, 149},     // C0
    {0x92AB, 2, 867},     // R0
    {0x92AD, 2, 4030},    // T0
    {0x92AF, 2, 316},     // R1
    {0x92B1, 1, 9},       // TC
    {0x92B2, 1, 0},       // C1
    {0x92BD, 2, 4173},    // StartDOD0
    {0x92BF, 2, 4043},    // StartDOD10
    {0x92C1, 2, 3925},    // StartDOD20
    {0x92C3, 2, 3821},    // StartDOD30
    {0x92C5, 2, 3725},    // StartDOD40
    {0x92C7, 2, 3665},    // StartDOD50
    {0x92C9, 2, 3619},    // StartDOD60
    {0x92CB, 2, 3585},    // StartDOD70
    {0x92CD, 2, 3515},    // StartDOD80
    {0x92CF, 2, 3439},    // StartDOD90
    {0x92D1, 2, 2713},    // StartDOD100
    {0x92B4, 2, 3031},    // EDV0
    {0x92B7, 2, 3385},    // EDV1
    {0x92BA, 2, 3501},    // EDV2
    {0x91DE, 1, 1},       // CalibrationCurrentDeadband
    {0x9217, 2, 1},       // ConfigurationPowerSleepCurrent
};

// Retry budget shared by both primitives below. Testing on this board showed
// ESP_ERR_INVALID_STATE from the ESP32-S3 Arduino core's I2C driver on
// essentially any transaction in this provisioning sequence -- not tied to
// one particular write or read -- at a low but real rate. Retrying here, at
// the lowest level both bq27220ControlSubCmd and every status/data-memory
// read/write funnel through, fixes it everywhere at once instead of needing
// a retry loop hand-added at each call site (device-number, full-access,
// seal, ... every one of them was hitting this independently).
constexpr uint8_t BQ27220_I2C_RETRY_ATTEMPTS = 5;
constexpr unsigned long BQ27220_I2C_RETRY_DELAY_MS = 10;

bool bq27220WriteBytes(uint8_t addr, uint8_t reg, const uint8_t* data, uint8_t len) {
  if (addr == 0) return false;
  I2cBusLock lock;
  ensureWire();
  for (uint8_t attempt = 0; attempt < BQ27220_I2C_RETRY_ATTEMPTS; ++attempt) {
    if (attempt > 0) delay(BQ27220_I2C_RETRY_DELAY_MS);
    TwoWire& w = gaugeWire();
    w.beginTransmission(addr);
    w.write(reg);
    for (uint8_t i = 0; i < len; ++i) w.write(data[i]);
    if (w.endTransmission(true) == 0) return true;
  }
  return false;
}

bool bq27220ReadBytes(uint8_t addr, uint8_t reg, uint8_t* dest, uint8_t len) {
  if (addr == 0) return false;
  I2cBusLock lock;
  ensureWire();
  for (uint8_t attempt = 0; attempt < BQ27220_I2C_RETRY_ATTEMPTS; ++attempt) {
    if (attempt > 0) delay(BQ27220_I2C_RETRY_DELAY_MS);
    TwoWire& w = gaugeWire();
    w.beginTransmission(addr);
    w.write(reg);
    if (w.endTransmission(true) != 0) continue;
    if (w.requestFrom(addr, len) < len) continue;
    for (uint8_t i = 0; i < len; ++i) dest[i] = w.read();
    return true;
  }
  return false;
}

bool bq27220ControlSubCmd(uint8_t addr, uint16_t subCmd) {
  const uint8_t buf[2] = {static_cast<uint8_t>(subCmd & 0xFF), static_cast<uint8_t>(subCmd >> 8)};
  return bq27220WriteBytes(addr, BQ27220_CMD_CONTROL, buf, 2);
}

// 16-bit read via bq27220ReadBytes's full-stop-then-new-start sequence, NOT
// this file's readReg16 (repeated start, no stop). readReg16 is fine for the
// plain command registers read elsewhere in this file (voltage/current/SoC),
// but every status/control/MAC-area read here follows a subcommand write,
// and the vendor driver this was ported from (LilyGo's lib/BQ27220) always
// puts a full stop between that write and the read that follows it. Using
// the repeated-start helper here instead was the actual cause of the
// intermittent ESP_ERR_INVALID_STATE seen in testing -- not a bus fluke.
bool bq27220ReadU16(uint8_t addr, uint8_t reg, uint16_t& out) {
  uint8_t data[2] = {0, 0};
  if (!bq27220ReadBytes(addr, reg, data, 2)) return false;
  out = static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
  return true;
}

bool bq27220GetSec(uint8_t addr, uint8_t& sec) {
  uint16_t status = 0;
  if (!bq27220ReadU16(addr, BQ27220_CMD_OPERATION_STATUS, status)) return false;
  sec = static_cast<uint8_t>((status & BQ27220_OPSTATUS_SEC_MASK) >> BQ27220_OPSTATUS_SEC_SHIFT);
  return true;
}

// Polls OperationStatus until `done` is satisfied or timeoutMs elapses.
// `lastStatus`, when given, is left holding the most recent successfully-read
// status even on timeout -- otherwise a timeout tells us nothing about
// whether the chip was close to `done` or stuck in some other state.
bool bq27220WaitForStatus(uint8_t addr, bool (*done)(uint16_t), unsigned long timeoutMs,
                           uint16_t* lastStatus = nullptr) {
  const unsigned long deadline = millis() + timeoutMs;
  do {
    uint16_t status = 0;
    if (bq27220ReadU16(addr, BQ27220_CMD_OPERATION_STATUS, status)) {
      if (lastStatus) *lastStatus = status;
      if (done(status)) return true;
    }
    delay(1);
  } while (millis() < deadline);
  return false;
}

bool bq27220Unseal(uint8_t addr) {
  uint8_t sec = 0;
  if (!bq27220GetSec(addr, sec)) return false;
  if (sec != BQ27220_SEC_SEALED) return true;
  bq27220ControlSubCmd(addr, BQ27220_CONTROL_UNSEAL_KEY1);
  delay(5);
  bq27220ControlSubCmd(addr, BQ27220_CONTROL_UNSEAL_KEY2);
  delay(5);
  if (!bq27220GetSec(addr, sec)) return false;
  return sec == BQ27220_SEC_UNSEALED;
}

bool bq27220FullAccess(uint8_t addr) {
  uint8_t sec = 0;
  if (!bq27220GetSec(addr, sec)) return false;
  if (sec == BQ27220_SEC_FULL) return true;
  if (sec != BQ27220_SEC_UNSEALED) return false;
  bq27220ControlSubCmd(addr, BQ27220_CONTROL_FULL_ACCESS_KEY);
  delay(5);
  bq27220ControlSubCmd(addr, BQ27220_CONTROL_FULL_ACCESS_KEY);
  delay(5);
  if (!bq27220GetSec(addr, sec)) return false;
  return sec == BQ27220_SEC_FULL;
}

// fullAccess()/seal() are each a quick, idempotent check-and-set: read the
// security state, and if not already there, write one or two key subcommands
// and read again. Every individual I2C transaction inside them already
// retries at the primitive level (bq27220WriteBytes/ReadBytes), but that
// doesn't help if the still-unresolved Arduino-ESP32 3.x "i2c-ng" driver bug
// (ESP_ERR_INVALID_STATE from i2c_master's internal timing setup --
// espressif/arduino-esp32#11374, not fixed by the latest available platform
// release) is hit on every one of the ~5 retry attempts for a single
// transaction -- rare per transaction, but with several transactions in one
// stage it adds up. Retrying the whole stage costs nothing when it's already
// satisfied (each returns true immediately on the first call) and
// meaningfully compounds the odds of getting through it, instead of failing
// the entire provisioning attempt over one bad moment and waiting for the
// outer ~1s gate to retry everything from scratch.
bool bq27220RetryStage(bool (*stage)(uint8_t), uint8_t addr, uint8_t attempts = 3,
                        unsigned long delayMs = 50) {
  for (uint8_t i = 0; i < attempts; ++i) {
    if (i > 0) delay(delayMs);
    if (stage(addr)) return true;
  }
  return false;
}

bool bq27220Seal(uint8_t addr) {
  uint8_t sec = 0;
  if (!bq27220GetSec(addr, sec)) return false;
  if (sec == BQ27220_SEC_SEALED) return true;
  bq27220ControlSubCmd(addr, BQ27220_CONTROL_SEALED);
  delay(1);
  if (!bq27220GetSec(addr, sec)) return false;
  return sec == BQ27220_SEC_SEALED;
}

bool bq27220Reset(uint8_t addr) {
  bq27220ControlSubCmd(addr, BQ27220_CONTROL_RESET);
  // 0xFFFF sentinel: distinguishes "timed out without ever reading status
  // successfully" from "read status fine the whole time, it just never
  // showed INITCOMP" -- the two point at very different problems.
  uint16_t lastStatus = 0xFFFF;
  const bool ok = bq27220WaitForStatus(
      addr, [](uint16_t status) { return (status & BQ27220_OPSTATUS_INITCOMP) != 0; }, 4000, &lastStatus);
#if defined(ENABLE_SERIAL_LOG)
  if (!ok) {
    esp_rom_printf("[BATT] BQ27220 reset timed out, last opStatus=0x%04X\n", lastStatus);
  }
#endif
  return ok;
}

// Writes (or, with write=false, verifies) one data-memory entry. TI's data-
// flash words are big-endian; the command registers read elsewhere in this
// file (BQ27220_VOLTAGE etc.) are little-endian -- different address spaces,
// different byte order, both correct as written.
bool bq27220DmParam(uint8_t addr, uint16_t dmAddr, uint32_t value, uint8_t size, bool write) {
  uint8_t buffer[6] = {0};
  buffer[0] = static_cast<uint8_t>(dmAddr & 0xFF);
  buffer[1] = static_cast<uint8_t>((dmAddr >> 8) & 0xFF);
  for (uint8_t i = 0; i < size; ++i) {
    buffer[1 + size - i] = static_cast<uint8_t>((value >> (i * 8)) & 0xFF);
  }

  if (write) {
    if (!bq27220WriteBytes(addr, BQ27220_CMD_SELECT_SUBCLASS, buffer, static_cast<uint8_t>(size + 2))) {
      return false;
    }
    delay(1);
    uint8_t checksum = 0;
    for (uint8_t i = 0; i < size + 2; ++i) checksum += buffer[i];
    checksum = static_cast<uint8_t>(0xFF - checksum);
    buffer[0] = checksum;
    buffer[1] = static_cast<uint8_t>(2 + size + 1 + 1);
    if (!bq27220WriteBytes(addr, BQ27220_CMD_MAC_DATA_SUM, buffer, static_cast<uint8_t>(size + 2))) {
      return false;
    }
    delay(10);
    return true;
  }

  if (!bq27220WriteBytes(addr, BQ27220_CMD_SELECT_SUBCLASS, buffer, 2)) return false;
  delay(1);
  uint8_t readBack[4] = {0};
  if (!bq27220ReadBytes(addr, BQ27220_CMD_MAC_DATA, readBack, size)) return false;
  for (uint8_t i = 0; i < size; ++i) {
    if (readBack[i] != buffer[2 + i]) return false;
  }
  return true;
}

// Applies (write=true) or verifies (write=false) the whole table in one
// config-update session.
bool bq27220ApplyOrVerifyDataMemory(uint8_t addr, bool write) {
  if (write) {
    bq27220ControlSubCmd(addr, BQ27220_CONTROL_ENTER_CFG_UPDATE);
    if (!bq27220WaitForStatus(
            addr, [](uint16_t s) { return (s & BQ27220_OPSTATUS_CFGUPDATE) != 0; }, 2000)) {
      return false;
    }
  }

  bool ok = true;
  for (const auto& entry : BQ27220_DATA_MEMORY) {
    if (!bq27220DmParam(addr, entry.address, entry.value, entry.size, write)) ok = false;
  }

  if (write && ok) {
    bq27220ControlSubCmd(addr, BQ27220_CONTROL_EXIT_CFG_UPDATE_REINIT);
    delay(2000);  // gauge needs this to re-learn against the new profile before answering again.
    if (!bq27220WaitForStatus(
            addr, [](uint16_t s) { return (s & BQ27220_OPSTATUS_CFGUPDATE) == 0; }, 2000)) {
      return false;
    }
  }
  return ok;
}

// readReg16 with a few retries. The ESP32-S3's I2C driver can return a
// transient ESP_ERR_INVALID_STATE from a non-stop write-read combined
// transaction when it lands too soon after a preceding stop-terminated
// write (seen in practice right after the DEVICE_NUMBER subcommand below) --
// harmless and self-clearing, but worth absorbing here rather than failing
// the whole provisioning attempt (and re-running the unseal/reset dance a
// second later) over one bus hiccup.
bool bq27220ReadReg16Retry(uint8_t addr, uint8_t reg, uint16_t& out, uint8_t attempts = 5) {
  for (uint8_t i = 0; i < attempts; ++i) {
    if (bq27220ReadU16(addr, reg, out)) return true;
    delay(5);
  }
  return false;
}

// Checks whether the gauge's resident data memory already matches
// BQ27220_DATA_MEMORY and, only if it does not, unseals/resets/rewrites it.
// Safe to call every boot: a gauge that already matches just gets a quick
// read-only verify and a seal.
bool bq27220EnsureProfile(uint8_t addr) {
  // Let whatever transaction readGaugeCharging()/readGaugeMillivolts() just
  // ran against this same bus (same gauge address, interleaved with the
  // charger's own address) fully settle before this function's first I2C
  // call. Testing showed the very first op here -- sometimes the write,
  // sometimes the read right after it -- intermittently returns
  // ESP_ERR_INVALID_STATE from the ESP32-S3 I2C driver; a short pause here
  // costs nothing (this path only runs once per second at most) and is the
  // standard mitigation for that class of driver issue.
  delay(20);

  uint16_t devId = 0;
  bool haveDevId = false;
  bool wroteSubCmd = false;
  for (uint8_t attempt = 0; attempt < 5 && !haveDevId; ++attempt) {
    if (attempt > 0) delay(20);
    wroteSubCmd = bq27220ControlSubCmd(addr, BQ27220_CONTROL_DEVICE_NUMBER);
    if (!wroteSubCmd) continue;
    delay(5);
    haveDevId = bq27220ReadU16(addr, BQ27220_CMD_MAC_DATA, devId) && devId == BQ27220_DEVICE_ID;
  }
#if defined(ENABLE_SERIAL_LOG)
  if (!haveDevId) {
    esp_rom_printf("[BATT] BQ27220 device-number check failed: last subcmd write %s, devId=0x%04X\n",
                    wroteSubCmd ? "ok" : "failed", devId);
  }
#endif
  if (!haveDevId) return false;

// One-shot trace through the rest of this function: every failure exit logs
// which stage it was, so a failure past the device-number check (the one
// case the log above doesn't explain) is identified immediately instead of
// needing another round of guess-a-patch-and-retest.
#if defined(ENABLE_SERIAL_LOG)
#define BQ27220_TRACE_FAIL(stage)                                       \
  do {                                                                  \
    esp_rom_printf("[BATT] BQ27220 provisioning stopped at: %s\n", stage); \
  } while (0)
#else
#define BQ27220_TRACE_FAIL(stage) \
  do {                            \
  } while (0)
#endif

  if (!bq27220Unseal(addr)) {
    BQ27220_TRACE_FAIL("unseal");
    return false;
  }

  uint16_t opStatus = 0;
  if (!bq27220ReadReg16Retry(addr, BQ27220_CMD_OPERATION_STATUS, opStatus)) {
    BQ27220_TRACE_FAIL("read operation status");
    return false;
  }
  bool needsProvisioning =
      (opStatus & BQ27220_OPSTATUS_INITCOMP) == 0 || (opStatus & BQ27220_OPSTATUS_CFGUPDATE) != 0;

  uint16_t ctrlStatus = 0;
  if (!bq27220ReadReg16Retry(addr, BQ27220_CMD_CONTROL, ctrlStatus)) {
    BQ27220_TRACE_FAIL("read control status");
    return false;
  }
  if ((ctrlStatus & BQ27220_CTRLSTATUS_BATT_ID_MASK) != 0) needsProvisioning = true;

  if (!needsProvisioning && !bq27220ApplyOrVerifyDataMemory(addr, /*write=*/false)) {
    needsProvisioning = true;
  }

#if defined(ENABLE_SERIAL_LOG)
  esp_rom_printf("[BATT] BQ27220 opStatus=0x%04X ctrlStatus=0x%04X needsProvisioning=%u\n", opStatus, ctrlStatus,
                  needsProvisioning ? 1 : 0);
#endif

  if (needsProvisioning) {
    // Best-effort, not a gate: the vendor's own reference init() (LilyGo's
    // lib/BQ27220, BQ27220::init()) calls reset() here and only logs on
    // failure -- it does NOT bail out, and proceeds to fullAccess() and the
    // data-memory write regardless. On this board reset()'s OperationStatus
    // never shows the expected INITCOMP transition within its timeout (opStatus
    // reads back identical for the full 4s), matching the vendor's own comment
    // doubting whether even the following fullAccess() call is necessary. What
    // actually provisions the gauge is fullAccess() + the data-memory write
    // below, not this step completing.
    if (!bq27220Reset(addr)) {
      BQ27220_TRACE_FAIL("reset (continuing anyway, as the vendor's own init() does)");
    }
    if (!bq27220RetryStage(bq27220FullAccess, addr)) {
      BQ27220_TRACE_FAIL("full access");
      return false;
    }
    bq27220ApplyOrVerifyDataMemory(addr, /*write=*/true);
    if (!bq27220ApplyOrVerifyDataMemory(addr, /*write=*/false)) {
      BQ27220_TRACE_FAIL("data memory write/verify");
      return false;
    }
  }

  if (!bq27220RetryStage(bq27220Seal, addr)) {
    BQ27220_TRACE_FAIL("seal");
    return false;
  }
  return true;
#undef BQ27220_TRACE_FAIL
}

// SoC (0..100) from the active gauge, dispatched by type. false on I2C failure.
bool readGaugeSoc(uint16_t& out) {
  const auto& g = BoardConfig::ACTIVE.batteryGauge;
#if FREEINK_DEVICE_WS397
  if (g.gaugeType == BoardConfig::GaugeType::Axp2101) {
    uint8_t soc = 0;
    if (!freeink::axp2101::batteryPercent(soc)) return false;
    out = soc;
    return true;
  }
#endif
  if (g.gaugeType == BoardConfig::GaugeType::Cw2017) {
    static bool initialized = false;
    static unsigned long lastInitAttemptMs = 0;

    const unsigned long now = millis();
    if (!initialized) {
      if (lastInitAttemptMs != 0 && (now - lastInitAttemptMs) < CW2017_INIT_RETRY_MS) return false;
      lastInitAttemptMs = now;
      initialized = cw2017EnsureProfile(g.gaugeAddr);
      if (!initialized) return false;
    }

    // Do not treat an acknowledged but sleeping/not-ready gauge as a fresh SoC
    // source. Clearing initialized makes the next call run the bounded recovery.
    uint8_t mode = 0;
    uint8_t version = 0;
    uint8_t soc = 0;
    if (!readReg8(g.gaugeAddr, CW2017_REG_MODE, mode) || mode != CW2017_MODE_NORMAL ||
        !readReg8(g.gaugeAddr, CW2017_REG_VERSION, version) || !cw2017VersionIsRunning(version) ||
        !readReg8(g.gaugeAddr, CW2017_REG_SOC, soc) || soc > 100) {
      initialized = false;
      return false;
    }

    out = soc;
    return true;
  }
  // One-time (per boot) data-memory provisioning: see bq27220EnsureProfile's
  // own comment for why this fixes the reported-percentage-vs-real-voltage
  // mismatch. Same bounded-retry shape as cw2017EnsureProfile above -- a
  // transient I2C error on the very first call must not be cached as
  // permanent failure.
  static bool bq27220Initialized = false;
  static unsigned long bq27220LastInitAttemptMs = 0;
  if (!bq27220Initialized) {
    const unsigned long now = millis();
    if (bq27220LastInitAttemptMs != 0 && (now - bq27220LastInitAttemptMs) < 1000) return false;
    bq27220LastInitAttemptMs = now;
    bq27220Initialized = bq27220EnsureProfile(g.gaugeAddr);
#if defined(ENABLE_SERIAL_LOG)
    esp_rom_printf("[BATT] BQ27220 data-memory provisioning: %s\n",
                    bq27220Initialized ? "ok (matches target profile)" : "failed, retrying");
#endif
    if (!bq27220Initialized) return false;
  }

  uint16_t soc = 0;
  if (!readReg16(g.gaugeAddr, BQ27220_STATE_OF_CHARGE, soc)) {
#if defined(ENABLE_SERIAL_LOG)
    // Diagnostic only (card: battery stops reporting a charge around 35%). If
    // this fires repeatedly while the charger-side log above keeps saying
    // fast-charge, the on-screen percentage is frozen because the gauge
    // stopped answering, not because the pack is actually done charging.
    esp_rom_printf("[BATT] BQ27220 SoC read (addr 0x%02X reg 0x%02X) failed\n", g.gaugeAddr,
                    BQ27220_STATE_OF_CHARGE);
#endif
    return false;
  }
  out = soc > 100 ? 100 : soc;
  return true;
}

// SoC in Q8 (percent << 8 | 1/256ths) from the active gauge. false on failure.
//
// Only the CW2017 carries a fraction; every other backend reports whole percent
// shifted up, so callers get one unit everywhere and never have to ask which
// gauge answered. The validity checks are the integer reader's, because a
// fraction from a sleeping or half-initialised gauge is not more trustworthy
// for being finer.
bool readGaugeSocQ8(uint16_t& out) {
  const auto& g = BoardConfig::ACTIVE.batteryGauge;
  if (g.gaugeType == BoardConfig::GaugeType::Cw2017) {
    // readGaugeSoc() owns the mode/version/range checks and the bounded
    // re-init, so the integer part comes from there rather than being read
    // again here with weaker validation.
    uint16_t soc = 0;
    if (!readGaugeSoc(soc)) return false;
    uint8_t frac = 0;
    // A fraction that will not read is not a failure: the integer part is
    // still the number every other caller uses, so report it with a zero
    // fraction rather than losing the reading entirely. The two registers are
    // read separately, so a carry between them can cost one LSB; that is 1/256
    // of a percent and below the noise of anything this is used for.
    if (!readReg8(g.gaugeAddr, CW2017_REG_SOC_FRAC, frac)) frac = 0;
    out = static_cast<uint16_t>(soc << 8) | frac;
    return true;
  }
  uint16_t soc = 0;
  if (!readGaugeSoc(soc)) return false;
  out = static_cast<uint16_t>(soc << 8);
  return true;
}

// Battery voltage (mV) from the active gauge, dispatched by type. false on failure.
bool readGaugeMillivolts(uint16_t& out) {
  const auto& g = BoardConfig::ACTIVE.batteryGauge;
#if FREEINK_DEVICE_WS397
  if (g.gaugeType == BoardConfig::GaugeType::Axp2101) return freeink::axp2101::batteryMillivolts(out);
#endif
  if (g.gaugeType == BoardConfig::GaugeType::Cw2017) {
    uint8_t hi = 0, lo = 0;
    if (!readReg8(g.gaugeAddr, CW2017_REG_VCELL_H, hi)) return false;
    if (!readReg8(g.gaugeAddr, static_cast<uint8_t>(CW2017_REG_VCELL_H + 1), lo)) return false;
    const uint16_t raw14 = static_cast<uint16_t>((hi & 0x3F) << 8) | lo;
    out = static_cast<uint16_t>((raw14 * 5 + 8) >> 4);  // OEM formula (~0.3125 mV/LSB, rounded)
    return true;
  }
  uint16_t mv = 0;
  if (!readReg16(g.gaugeAddr, BQ27220_VOLTAGE, mv)) return false;
  out = mv;
  return true;
}

// Charging state for an I2C-gauge board, from the active board's gauge config.
// Two sources, in order of preference:
//   1. A dedicated charger IC (BQ25896): CHRG_STAT in REG0B[4:3] — 01 pre-charge
//      or 10 fast-charge means charging. Used by LilyGo T5 S3.
//   2. Gauge-native fallback (BQ27220 Current(), signed mA): current flowing INTO
//      the battery (> 0) means charging. Lets boards with a gauge but NO charger
//      IC — e.g. Xteink X3 — still report charge status. Current() is used rather
//      than the BatteryStatus DSG bit because DSG also clears during rest, so it
//      can't tell "charging" from "idle"; the current sign can.
// `known` is set false only when neither source responds (transient I2C failure or
// a board with neither gaugeAddr nor chargerAddr).
bool readGaugeCharging(bool& known) {
  const auto& g = BoardConfig::ACTIVE.batteryGauge;
#if FREEINK_DEVICE_WS397
  if (g.gaugeType == BoardConfig::GaugeType::Axp2101) return freeink::axp2101::isCharging(known);
#endif
  // CW2017 has no current register and the X4 Pro has no charger IC on this bus, so
  // charging state is not observable from the gauge (the OEM infers it elsewhere).
  if (g.gaugeType == BoardConfig::GaugeType::Cw2017) {
    known = false;
    return false;
  }
  if (g.chargerAddr != 0) {
    uint8_t status = 0;
    if (readReg8(g.chargerAddr, BQ25896_REG_STATUS, status)) {
      known = true;
      const uint8_t chrg = (status >> 3) & 0x03;
      // Diagnostic only (card: battery stops reporting a charge around 35%).
      // CHRG_STAT: 00 not charging, 01 pre-charge, 10 fast charge, 11 charge
      // termination done. Throttled to once every 30s so a full charge cycle
      // produces a short, readable trace in `pio device monitor` instead of a
      // line per poll. This distinguishes "the BQ25896 itself ended the
      // charge" (chrg == 0b11, a real charger-side termination to chase in the
      // charger's own config/thermal/ITERM behavior) from "the gauge stopped
      // answering" (readGaugeSoc() failing below, chrg still 0b10) -- those
      // look identical on-screen but need different fixes.
#if defined(ENABLE_SERIAL_LOG)
      static unsigned long lastLogMs = 0;
      static uint8_t lastChrg = 0xFF;
      const unsigned long now = millis();
      if (chrg != lastChrg || (now - lastLogMs) >= 30000) {
        // VBUS_STAT/PG_STAT bit positions per readChargerExternalPower()'s own
        // comment above, read from the same register for one consistent decode.
        const uint8_t vbus = (status >> 5) & 0x07;
        const bool powerGood = (status & 0x04) != 0;
        // Ground truth for the "35%, not a real full charge" question: the
        // BQ27220 measures the BATTERY directly (not VBUS), on the same
        // bus/cadence as the charger status above, so a voltage this close to
        // REG06's VREG (see the one-time config dump below) at a low SoC
        // means the pack genuinely reached that voltage early -- consistent
        // with either a degraded/lower-capacity cell or excess series
        // resistance, not a software misread of a healthy battery.
        uint16_t vmv = 0;
        uint16_t rawCur = 0;
        const bool haveV = readReg16(g.gaugeAddr, BQ27220_VOLTAGE, vmv);
        const bool haveI = readReg16(g.gaugeAddr, BQ27220_CURRENT, rawCur);
        esp_rom_printf(
            "[BATT] BQ25896 REG0B=0x%02X VBUS_STAT=%u PG=%u CHRG_STAT=%u (%s) | BQ27220 VBAT=%dmV I=%dmA\n",
            status, vbus, powerGood ? 1 : 0, chrg,
            chrg == 0x00   ? "not-charging"
            : chrg == 0x01 ? "pre-charge"
            : chrg == 0x02 ? "fast-charge"
                           : "done/terminated",
            haveV ? static_cast<int>(vmv) : -1, haveI ? static_cast<int>(static_cast<int16_t>(rawCur)) : -1);
        lastLogMs = now;
        lastChrg = chrg;
      }
      // One-time dump of the registers that actually decide WHEN it terminates:
      // input current limit, fast-charge current, termination current, and
      // target (float) charge voltage. Firmware never writes any of these --
      // this board runs entirely on whatever the BQ25896 powered up with -- so
      // if chrg == 0b11 (done) at an SoC that doesn't look like a real full
      // battery, these are the values to check against the battery's actual
      // rating rather than guessing. Read once (config doesn't change at
      // runtime here) rather than on the 30s throttle above.
      static bool dumpedConfig = false;
      if (!dumpedConfig) {
        dumpedConfig = true;
        uint8_t reg00 = 0, reg04 = 0, reg05 = 0, reg06 = 0;
        const bool ok00 = readReg8(g.chargerAddr, 0x00, reg00);
        const bool ok04 = readReg8(g.chargerAddr, 0x04, reg04);
        const bool ok05 = readReg8(g.chargerAddr, 0x05, reg05);
        const bool ok06 = readReg8(g.chargerAddr, 0x06, reg06);
        if (ok00 && ok04 && ok05 && ok06) {
          const bool hiz = (reg00 & 0x80) != 0;
          const unsigned iinlimMa = 100u + (reg00 & 0x3F) * 50u;
          const unsigned ichgMa = (reg04 & 0x7F) * 64u;
          const unsigned itermMa = 64u + (reg05 & 0x0F) * 64u;
          const unsigned iprechgMa = 64u + ((reg05 >> 4) & 0x0F) * 64u;
          const unsigned vregMv = 3840u + ((reg06 >> 2) & 0x3F) * 16u;
          esp_rom_printf(
              "[BATT] BQ25896 config: REG00=0x%02X HIZ=%u IINLIM=%umA | REG04=0x%02X ICHG=%umA | "
              "REG05=0x%02X IPRECHG=%umA ITERM=%umA | REG06=0x%02X VREG=%umV\n",
              reg00, hiz ? 1 : 0, iinlimMa, reg04, ichgMa, reg05, iprechgMa, itermMa, reg06, vregMv);
        } else {
          esp_rom_printf("[BATT] BQ25896 config register read failed (REG00=%d REG04=%d REG05=%d REG06=%d)\n",
                          ok00, ok04, ok05, ok06);
        }
      }
#endif
      return chrg == 0x01 || chrg == 0x02;
    }
#if defined(ENABLE_SERIAL_LOG)
    esp_rom_printf("[BATT] BQ25896 status read (addr 0x%02X reg 0x%02X) failed\n", g.chargerAddr,
                    BQ25896_REG_STATUS);
#endif
  }
  uint16_t raw = 0;
  if (readReg16(g.gaugeAddr, BQ27220_CURRENT, raw)) {
    known = true;
    return static_cast<int16_t>(raw) > 0;
  }
  known = false;
  return false;
}

// External-power presence from the charger IC, out of the SAME REG0B read that
// readGaugeCharging() uses for CHRG_STAT:
//   VBUS_STAT [7:5] — 000 no input, 001 USB host SDP, 010 USB CDP, 011 adapter,
//                     111 OTG (we are SOURCING power, not receiving it)
//   PG_STAT   [2]   — power good
// Anything but "no input" and "OTG" means a cable is supplying us. Unlike
// charge state this stays true at 100%, which is exactly the case that makes
// charge-based USB inference wrong.
//
// Only the BQ25896 answers this. The BQ27220 gauge measures the BATTERY, not
// the input rail, so there is deliberately no gauge fallback here — reporting
// "no external power" from a gauge that cannot see the input would be a lie.
bool readChargerExternalPower(bool& known) {
  const auto& g = BoardConfig::ACTIVE.batteryGauge;
  if (g.chargerAddr == 0) {
    known = false;
    return false;
  }
  uint8_t status = 0;
  if (!readReg8(g.chargerAddr, BQ25896_REG_STATUS, status)) {
    known = false;
    return false;
  }
  known = true;
  const uint8_t vbus = (status >> 5) & 0x07;
  const bool powerGood = (status & 0x04) != 0;
  return (vbus != 0x00 && vbus != 0x07) || powerGood;
}
}  // namespace
#endif  // FREEINK_BATTERY_I2C_GAUGE

namespace {
constexpr uint8_t M5PM1_REG_PWR_SRC = 0x04;
constexpr uint8_t M5PM1_REG_VREF_L = 0x20;
constexpr uint8_t M5PM1_PWR_SRC_5VIN = 1u << 0;
constexpr uint8_t M5PM1_PWR_SRC_5VINOUT = 1u << 1;

uint16_t readLe16(const uint8_t* bytes) {
  return static_cast<uint16_t>(bytes[0]) | (static_cast<uint16_t>(bytes[1]) << 8);
}
}  // namespace

BatteryMonitor::BatteryMonitor()
    : BatteryMonitor(BoardConfig::ACTIVE.batteryAdc, BoardConfig::ACTIVE.batteryDividerMultiplier,
                     BoardConfig::ACTIVE.batteryChargeStatus) {}

namespace {
// Level meaning "charging" on the charge-status pin, per the active board's
// polarity. Active-low /STAT lines are open-drain and need the internal
// pull-up; an active-high STAT (X4 Pro GPIO21) is push-pull driven with no
// pull — stock reads it bare, and a pull-up would fake "charging" if the
// driver ever tri-states.
int chargeActiveLevel() {
  return BoardConfig::ACTIVE.batteryChargeStatusActiveHigh ? HIGH : LOW;
}
}  // namespace

BatteryMonitor::BatteryMonitor(int8_t adcPin, float dividerMultiplier, int8_t chargeStatusPin)
    : _adcPin(adcPin), _dividerMultiplier(dividerMultiplier), _chargeStatusPin(chargeStatusPin) {
  if (_chargeStatusPin >= 0) {
    pinMode(_chargeStatusPin, BoardConfig::ACTIVE.batteryChargeStatusActiveHigh ? INPUT : INPUT_PULLUP);
  }
}

bool BatteryMonitor::hasAdcBackend() const {
  return _adcPin >= 0;
}

bool BatteryMonitor::hasGaugeBackend() const {
#if FREEINK_BATTERY_I2C_GAUGE
  return BoardConfig::ACTIVE.batteryGauge.gaugeAddr != 0;
#else
  return false;
#endif
}

bool BatteryMonitor::hasM5Pm1Backend() const {
  return BoardConfig::isM5StackPaperColor() || BoardConfig::isPaperMono();
}

uint16_t BatteryMonitor::readPercentage() const {
#if FREEINK_BATTERY_I2C_GAUGE
  // Runtime, per active profile: gauge boards (X3, LilyGo, X4 Pro) read SoC over I2C;
  // ADC boards (X4) in the same binary fall through to the divider path below.
  if (BoardConfig::ACTIVE.batteryGauge.gaugeAddr != 0) {
    uint16_t soc = 0;
    if (!readGaugeSoc(soc)) return 0;
    return soc;
  }
#endif
  if (hasM5Pm1Backend()) {
    Status status;
    if (readM5Pm1Status(status) && status.percentageKnown) return status.percentage;
    return 0;
  }
  if (!hasAdcBackend()) return 0;
  return percentageFromMillivolts(readMillivolts());
}

bool BatteryMonitor::readPercentageChecked(uint16_t& out) const {
#if FREEINK_BATTERY_I2C_GAUGE
  if (BoardConfig::ACTIVE.batteryGauge.gaugeAddr != 0) {
    uint16_t soc = 0;
    if (!readGaugeSoc(soc)) return false;
    out = soc;
    return true;
  }
#endif
  if (hasM5Pm1Backend()) {
    Status status;
    if (!readM5Pm1Status(status) || !status.percentageKnown) return false;
    out = status.percentage;
    return true;
  }
  if (!hasAdcBackend()) return false;
  out = percentageFromMillivolts(readMillivolts());
  return true;
}

bool BatteryMonitor::readSocQ8(uint16_t& out) const {
#if FREEINK_BATTERY_I2C_GAUGE
  if (BoardConfig::ACTIVE.batteryGauge.gaugeAddr != 0) return readGaugeSocQ8(out);
#endif
  // No gauge: the ADC and M5 paths have no sub-percent source, so shift the
  // percent they do have rather than inventing precision that is not there.
  uint16_t pct = 0;
  if (!readPercentageChecked(pct)) return false;
  out = static_cast<uint16_t>(pct << 8);
  return true;
}

BatteryMonitor::Status BatteryMonitor::readStatus() const {
  Status status;

#if FREEINK_BATTERY_I2C_GAUGE
  if (BoardConfig::ACTIVE.batteryGauge.gaugeAddr != 0) {
    status.supported = true;
    uint16_t soc = 0;
    if (readGaugeSoc(soc)) {
      status.percentageKnown = true;
      status.percentage = soc;
    }
    uint16_t mv = 0;
    if (readGaugeMillivolts(mv)) {
      status.millivoltsKnown = true;
      status.millivolts = mv;
    }
    // Charging: from a dedicated charger IC when present, else the gauge's own
    // Current() sign — so gauge-only boards (X3) report it too. A gauge that
    // cannot observe charging at all (CW2017) leaves chargingKnown false; fall
    // back to the charger's STAT pin when the board has one (X4 Pro GPIO21).
    bool chargingKnown = false;
    bool charging = readGaugeCharging(chargingKnown);
    if (!chargingKnown && _chargeStatusPin >= 0) {
      chargingKnown = true;
      charging = digitalRead(_chargeStatusPin) == chargeActiveLevel();
    }
    status.chargingKnown = chargingKnown;
    status.charging = charging;
    return status;
  }
#endif

  if (hasM5Pm1Backend()) {
    readM5Pm1Status(status);
    return status;
  }

  if (hasAdcBackend()) {
    status.supported = true;
    status.millivolts = readMillivolts();
    status.millivoltsKnown = status.millivolts > 0;
    if (status.millivoltsKnown) {
      status.percentage = percentageFromMillivolts(status.millivolts);
      status.percentageKnown = true;
    }
    if (_chargeStatusPin >= 0) {
      status.chargingKnown = true;
      status.charging = digitalRead(_chargeStatusPin) == chargeActiveLevel();
    }
  }
  return status;
}

uint16_t BatteryMonitor::readMillivolts() const {
#if FREEINK_BATTERY_I2C_GAUGE
  if (BoardConfig::ACTIVE.batteryGauge.gaugeAddr != 0) {
    uint16_t gaugeMv = 0;
    readGaugeMillivolts(gaugeMv);
    return gaugeMv;  // gauge reports true battery mV (no divider)
  }
#endif
  if (hasM5Pm1Backend()) {
    Status status;
    if (readM5Pm1Status(status) && status.millivoltsKnown) return status.millivolts;
    return 0;
  }
  if (!hasAdcBackend()) return 0;
#if ESP_IDF_VERSION_MAJOR < 5
  // ESP-IDF 4.x doesn't have analogReadMilliVolts, so calibrate manually.
  const uint16_t raw = analogRead(_adcPin);
  esp_adc_cal_characteristics_t adc_chars;
  esp_adc_cal_characterize(ADC_UNIT_1, ADC_ATTEN_DB_12, ADC_WIDTH_BIT_12, 1100, &adc_chars);
  const uint16_t mv = esp_adc_cal_raw_to_voltage(raw, &adc_chars);
#else
  // ESP-IDF 5.x has analogReadMilliVolts
  // OnePage only: pause charging around the read. Other boards with a
  // chargeEnable pin (e.g. Sticky) must NOT have it glitched during battery reads.
  uint16_t mv = 0;
  if (BoardConfig::isOnePage() && BoardConfig::ACTIVE.power.chargeEnable >= 0) {
    const int8_t ce = BoardConfig::ACTIVE.power.chargeEnable;
    const bool activeHigh = BoardConfig::ACTIVE.power.chargeEnableActiveHigh;
    pinMode(ce, OUTPUT);
    digitalWrite(ce, activeHigh ? LOW : HIGH);  // pause charging
    delay(5);
    mv = analogReadMilliVolts(_adcPin);
    digitalWrite(ce, activeHigh ? HIGH : LOW);  // resume charging
  } else {
    mv = analogReadMilliVolts(_adcPin);
  }
#endif

  return static_cast<uint16_t>(mv * _dividerMultiplier);
}

double BatteryMonitor::readVolts() const {
  return static_cast<double>(readMillivolts()) / 1000.0;
}

bool BatteryMonitor::isCharging() const {
#if FREEINK_BATTERY_I2C_GAUGE
  // Gauge boards: prefer a charger IC's status (BQ25896), else fall back to the
  // gauge's own Current() sign, so a board with a gauge but no charger IC (e.g.
  // X3) still reports charging. A gauge that cannot observe charging at all
  // (CW2017) reports unknown — fall through to the STAT pin below (X4 Pro
  // GPIO21). Failed reads report false.
  if (BoardConfig::ACTIVE.batteryGauge.gaugeAddr != 0) {
    bool known = false;
    const bool charging = readGaugeCharging(known);
    if (known) {
      return charging;
    }
  }
#endif
  if (hasM5Pm1Backend()) {
    Status status;
    return readM5Pm1Status(status) && status.chargingKnown && status.charging;
  }
  if (_chargeStatusPin < 0) {
    return false;
  }
  // STAT at its board-declared active level (default: MCP73832-style /STAT,
  // LOW while charging).
  return digitalRead(_chargeStatusPin) == chargeActiveLevel();
}

bool BatteryMonitor::isExternalPowerPresent(bool* known) const {
  bool observed = false;
#if FREEINK_BATTERY_I2C_GAUGE
  const bool present = readChargerExternalPower(observed);
  if (observed) {
    if (known) *known = true;
    return present;
  }
#endif
  if (hasM5Pm1Backend()) {
    // The M5 PMIC reports its supply source directly (PWR_SRC 5VIN/5VINOUT),
    // which readM5Pm1Status() already decodes into externalPower — the right
    // field here, rather than the `charging` one it derives from it.
    Status status;
    if (readM5Pm1Status(status) && status.externalPowerKnown) {
      if (known) *known = true;
      return status.externalPower;
    }
  }
  if (known) *known = false;
  return false;
}

bool BatteryMonitor::readM5Pm1Status(Status& status) const {
  status.supported = true;
  if (!hasM5Pm1Backend()) return false;

  freeink::m5pm1::beginBus();

  // VREF/VBAT/VIN/5VOUT are four complete 16-bit little-endian millivolt
  // registers (0x20..0x27). Only ADC_RES at 0x28 is 12-bit. Read the whole
  // block atomically so paired bytes and the three rails share one sample.
  uint8_t rails[8] = {};
  const bool railsKnown = freeink::m5pm1::readBytes(M5PM1_REG_VREF_L, rails, sizeof(rails));
  if (railsKnown) {
    const uint16_t batMv = readLe16(rails + 2);
    const uint16_t vinMv = readLe16(rails + 4);
    const uint16_t vinOutMv = readLe16(rails + 6);
    status.millivoltsKnown = true;
    status.millivolts = batMv;
    status.percentageKnown = true;
    status.percentage = percentageFromMillivolts(batMv);
    status.pm1VinMv = vinMv;
    status.pm1VinOutMv = vinOutMv;
  }

  uint8_t powerSource = 0;
  const bool pwrSrcKnown = freeink::m5pm1::readReg(M5PM1_REG_PWR_SRC, &powerSource);
  if (pwrSrcKnown) {
    const uint8_t sources = powerSource & 0x07;
    status.pm1PowerSource = sources;
    status.externalPowerKnown = true;
    // PM1 manual: PWR_SRC is a bitmap, not the enum used by older M5PM1
    // wrappers. Multiple bits may be set at once (the connected Paper Mono
    // reports 0x05 = BAT | 5VIN). Unlike the ADC rail samples, these validity
    // bits drop when the cable is removed, so they are the authoritative
    // source for the charging badge.
    status.externalPower = (sources & (M5PM1_PWR_SRC_5VIN | M5PM1_PWR_SRC_5VINOUT)) != 0;
  }

  // Product semantics for Paper Mono: external supply present means charging.
  status.chargingKnown = status.externalPowerKnown;
  status.charging = status.externalPower;
  return status.percentageKnown || status.millivoltsKnown || status.externalPowerKnown;
}

// Standard 1S Li-ion / LiPo (4.20 V) rest-voltage discharge curve, one entry per
// 10% notch. The curve is deliberately not resampled any finer: between 20% and
// 60% the whole span is ~130 mV, so a tenth of a volt-step is already below the
// noise of any of the three backends. A caller that needs real resolution should
// read millivolts and show those instead.
//
// The 0% anchor is 3.45 V rather than the cell's protection cut-off. Below that
// the pack falls off a cliff and the remaining runtime is minutes, so reporting
// it as empty is honest; it also leaves headroom for the sag under an e-ink
// refresh, which is the heaviest load this device draws.
constexpr uint16_t LIION_NOTCH_MV[11] = {
    3450,  //   0%
    3680,  //  10%
    3740,  //  20%
    3770,  //  30%
    3790,  //  40%
    3820,  //  50%
    3870,  //  60%
    3920,  //  70%
    3980,  //  80%
    4060,  //  90%
    4200,  // 100%
};

// A notch change has to clear the boundary by this much before it is accepted.
// The 20-40% band is only 50 mV wide, so without a deadband a few millivolts of
// sampler noise would swap the icon back and forth between page turns. Kept
// well under the narrowest half-segment (10 mV) so no notch can become a trap.
constexpr uint16_t NOTCH_HYSTERESIS_MV = 8;

uint16_t BatteryMonitor::percentageFromMillivolts(uint16_t millivolts) {
  // A failed read reports 0 mV, which lands on 0% here. That is deliberate: the
  // cubic this table replaced evaluated to +7501 at 0 V and clamped to a
  // confident 100%, so an I2C or ADC failure showed a full battery.
  if (millivolts >= LIION_NOTCH_MV[10]) return 100;
  // Round at the midpoint of each segment instead of flooring, so a cell resting
  // just below 4.20 V straight off the charger still reads 100%.
  for (uint8_t i = 10; i > 0; --i) {
    const uint16_t boundary = static_cast<uint16_t>((LIION_NOTCH_MV[i - 1] + LIION_NOTCH_MV[i]) / 2);
    if (millivolts >= boundary) return static_cast<uint16_t>(i * 10);
  }
  return 0;
}

uint16_t BatteryMonitor::percentageFromMillivolts(uint16_t millivolts, uint16_t previousPercent) {
  const uint16_t notch = percentageFromMillivolts(millivolts);
  if (previousPercent > 100) return notch;  // no usable history
  const uint16_t previousNotch = static_cast<uint16_t>((previousPercent / 10) * 10);
  if (notch == previousNotch) return notch;

  // Re-run the lookup with the sample pushed back toward the notch we are
  // leaving. If it still crosses, the move is real; if not, hold.
  const int32_t bias = notch > previousNotch ? -NOTCH_HYSTERESIS_MV : NOTCH_HYSTERESIS_MV;
  const int32_t biased = std::clamp<int32_t>(static_cast<int32_t>(millivolts) + bias, 0, UINT16_MAX);
  return percentageFromMillivolts(static_cast<uint16_t>(biased)) == notch ? notch : previousNotch;
}
