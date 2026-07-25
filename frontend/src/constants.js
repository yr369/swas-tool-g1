/**
 * constants.js - shared label maps for platform and scope target type,
 * kept in one place so every dropdown/filter/chip in the app stays in
 * sync with the backend's PlatformType/TargetType Literals (models.py).
 */

export const PLATFORM_LABEL = {
  bugcrowd: "Bugcrowd",
  hackerone: "HackerOne",
  intigriti: "Intigriti",
  yeswehack: "YesWeHack",
  openbugbounty: "OpenBugBounty",
  private: "Private",
};

export function platformLabel(p) {
  return PLATFORM_LABEL[p] || p;
}

export const TARGET_TYPES = [
  { value: "domain", label: "Domain" },
  { value: "wildcard", label: "Wildcard" },
  { value: "url", label: "URL" },
  { value: "api", label: "API" },
  { value: "android_play_store", label: "Android: Play Store" },
  { value: "ios_app_store", label: "iOS: App Store" },
  { value: "hardware_iot", label: "Hardware/IoT" },
  { value: "hardware", label: "Hardware" },
  { value: "smart_contract", label: "Smart contract" },
  { value: "source_code", label: "Source code" },
  { value: "executable", label: "Executable" },
  { value: "other", label: "Other" },
  { value: "unknown", label: "Unknown" },
];

export const TARGET_TYPE_LABEL = Object.fromEntries(TARGET_TYPES.map((t) => [t.value, t.label]));

export function targetTypeLabel(t) {
  return TARGET_TYPE_LABEL[t] || t;
}
