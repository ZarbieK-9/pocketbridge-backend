import fs from 'fs';
import path from 'path';

export interface BuildInfo {
  version: string;
  commit?: string;
  branch?: string;
  buildTime?: string;
}

let cachedInfo: BuildInfo | null = null;

export function getBuildInfo(): BuildInfo {
  if (cachedInfo) {
    return cachedInfo;
  }

  const info: BuildInfo = {
    version: process.env.BUILD_VERSION || process.env.npm_package_version || '1.0.0',
    commit: process.env.BUILD_COMMIT,
    branch: process.env.BUILD_BRANCH,
    buildTime: process.env.BUILD_TIME,
  };

  const infoPath = process.env.BUILD_INFO_PATH || path.resolve(process.cwd(), 'build-info.json');

  try {
    const raw = fs.readFileSync(infoPath, 'utf8');
    const parsed = JSON.parse(raw) as Partial<BuildInfo>;
    cachedInfo = {
      ...info,
      ...parsed,
    };
  } catch {
    cachedInfo = info;
  }

  return cachedInfo;
}