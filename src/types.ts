export interface Env {
  SODAPUSH_DB: D1Database;
  MASTER_KEY: string;
  BOOTSTRAP_TOKEN?: string;
  APP_VERSION?: string;
  PUSH_QUEUE?: Queue;
}

export interface SessionUser {
  id: string;
  username: string;
  role: "owner" | "admin" | "developer" | "viewer";
}

export interface DeviceRegistrationRequest {
  deviceToken: string;
  environment: "development" | "production";
  context: {
    platform: string;
    appVersion?: string | null;
    appBuild?: string | null;
    locale?: string | null;
    language?: string | null;
    timeZone?: string | null;
    userID?: string | null;
    tags?: string[];
  };
}

export interface ErrorBody {
  code: string;
  message: string;
  requestId: string;
}
