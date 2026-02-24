import type { HTTPCredentials } from 'playwright';
import type {
  LaunchOptions,
  CLIOptions,
  ConnectionType,
  BrowserName,
} from './types.js';
import { parseCLIOption, parseUnknown } from './validation.js';
import {
  CookiesSchema,
  HeadersSchema,
  AuthSchema,
  FirefoxPrefsSchema,
  OverrideHostSchema,
  StringArraySchema,
} from './schemas.js';

import { DEFAULT_OPTIONS } from './defaultOptions.js';

// Normalize raw CLI options into a typed LaunchOptions config.
export function normalizeCLIConfig(options: CLIOptions): LaunchOptions {
  const config: LaunchOptions = {
    url: options.url,
    browser: (options.browser as BrowserName) || DEFAULT_OPTIONS.browser,
    width: options.width ?? DEFAULT_OPTIONS.width,
    height: options.height ?? DEFAULT_OPTIONS.height,
    frameRate: options.frameRate ?? DEFAULT_OPTIONS.frameRate,
    timeout: options.timeout ?? DEFAULT_OPTIONS.timeout,
    blockDomains: options.blockDomains || DEFAULT_OPTIONS.blockDomains,
    block: options.block || DEFAULT_OPTIONS.block,
    disableJS: options.disableJS || DEFAULT_OPTIONS.disableJS,
    debug: options.debug || DEFAULT_OPTIONS.debug,
    html: options.html || DEFAULT_OPTIONS.html,
    openHtml: options.openHtml || DEFAULT_OPTIONS.openHtml,
    list: options.list || DEFAULT_OPTIONS.list,
    connectionType:
      (options.connectionType as ConnectionType) ||
      DEFAULT_OPTIONS.connectionType,
    auth: DEFAULT_OPTIONS.auth,
    zip: options.zip || DEFAULT_OPTIONS.zip,
    dry: options.dry || DEFAULT_OPTIONS.dry,
    delayUsing: DEFAULT_OPTIONS.delayUsing,
  };

  // Parse JSON strings from CLI (pass through objects from programmatic)
  if (options.cookies) {
    config.cookies = parseCLIOption('--cookies', options.cookies, CookiesSchema);
  }

  if (options.headers) {
    config.headers = parseCLIOption('--headers', options.headers, HeadersSchema);
  }

  if (options.auth) {
    config.auth = parseCLIOption('--auth', options.auth, AuthSchema);
  }

  if (options.delay) {
    config.delay = JSON.parse(options.delay) as Record<string, number>;
  }

  if (
    options.delayUsing &&
    (options.delayUsing === 'fulfill' || options.delayUsing === 'continue')
  ) {
    config.delayUsing = options.delayUsing;
  }

  if (options.firefoxPrefs) {
    config.firefoxPrefs = parseCLIOption('--firefoxPrefs', options.firefoxPrefs, FirefoxPrefsSchema);
  }

  if (options.overrideHost) {
    config.overrideHost = parseCLIOption('--overrideHost', options.overrideHost, OverrideHostSchema);
  }

  // flags already parsed to string[] by argParser
  if (options.flags) {
    config.args = options.flags;
  }

  // cpuThrottle already parsed to number by argParser
  if (options.cpuThrottle) {
    config.cpuThrottle = options.cpuThrottle;
  }

  if (options.block) {
    try {
      config.block = parseJSONArrayOrCommaSeparatedStrings('--block', options.block);
    } catch (err) {
      throw new Error(
        `Problem parsing "--block" options - ${(err as Error).message}`,
      );
    }
  }

  if (options.blockDomains) {
    try {
      config.blockDomains = parseJSONArrayOrCommaSeparatedStrings(
        '--blockDomains',
        options.blockDomains,
      );
    } catch (err) {
      throw new Error(
        `Problem parsing "--blockDomains" options - ${(err as Error).message}`,
      );
    }
  }

  // Validate uploadUrl if provided
  if (options.uploadUrl) {
    try {
      new URL(options.uploadUrl);
    } catch (err) {
      throw new Error(`--uploadUrl must be a valid URL`);
    }

    config.uploadUrl = options.uploadUrl;
  }

  return config;
}

function parseJSONArrayOrCommaSeparatedStrings(flagName: string, choices: string[]): string[] {
  const chosen: string[] = [];

  choices.forEach(opt_group => {
    if (opt_group.includes('[')) {
      // Looks like a JSON array
      const parsed: unknown = JSON.parse(opt_group);
      chosen.push(...parseUnknown(flagName, parsed, StringArraySchema));
    } else {
      opt_group.split(/,/).forEach(opt => {
        if (opt) {
          chosen.push(opt);
        }
      });
    }
  });

  return chosen;
}
