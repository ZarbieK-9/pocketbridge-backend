/**
 * Device Validation Utilities
 * 
 * Provides validation for device types and OS values
 * to ensure data integrity before database insertion
 */

export const VALID_DEVICE_TYPES = ['mobile', 'desktop', 'web'] as const;
export const VALID_OS_TYPES = ['ios', 'android', 'windows', 'macos', 'linux', 'web'] as const;

export type DeviceType = typeof VALID_DEVICE_TYPES[number];
export type OSType = typeof VALID_OS_TYPES[number];

/**
 * Validate device type
 */
export function isValidDeviceType(type: string | null | undefined): type is DeviceType {
  if (!type) return false;
  return VALID_DEVICE_TYPES.includes(type as DeviceType);
}

/**
 * Validate OS type
 */
export function isValidOSType(os: string | null | undefined): os is OSType {
  if (!os) return false;
  return VALID_OS_TYPES.includes(os as OSType);
}

/**
 * Validate and normalize device type
 * @throws ValidationError if invalid
 */
export function validateDeviceType(type: string | null | undefined): DeviceType {
  if (!isValidDeviceType(type)) {
    throw new Error(
      `Invalid device_type: "${type}". Must be one of: ${VALID_DEVICE_TYPES.join(', ')}`
    );
  }
  return type;
}

/**
 * Validate and normalize OS type
 * @throws ValidationError if invalid
 */
export function validateOSType(os: string | null | undefined): OSType {
  if (!isValidOSType(os)) {
    throw new Error(
      `Invalid device_os: "${os}". Must be one of: ${VALID_OS_TYPES.join(', ')}`
    );
  }
  return os;
}

/**
 * Infer device type from OS
 */
export function inferDeviceTypeFromOS(os: OSType): DeviceType {
  switch (os) {
    case 'ios':
    case 'android':
      return 'mobile';
    case 'windows':
    case 'macos':
    case 'linux':
      return 'desktop';
    case 'web':
      return 'web';
    default:
      return 'mobile'; // fallback
  }
}

/**
 * Get user-friendly device type name
 */
export function getDeviceTypeName(type: DeviceType): string {
  switch (type) {
    case 'mobile':
      return 'Mobile Device';
    case 'desktop':
      return 'Desktop Computer';
    case 'web':
      return 'Web Browser';
    default:
      return 'Device';
  }
}

/**
 * Get user-friendly OS name
 */
export function getOSName(os: OSType): string {
  switch (os) {
    case 'ios':
      return 'iOS';
    case 'android':
      return 'Android';
    case 'windows':
      return 'Windows';
    case 'macos':
      return 'macOS';
    case 'linux':
      return 'Linux';
    case 'web':
      return 'Web';
    default:
      return 'Unknown';
  }
}
