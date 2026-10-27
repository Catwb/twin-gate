export interface Env {
  CORE: Fetcher;
  ASSETS: Fetcher;
  GATEWAY_TOKEN: string;
  ISSUER: string;
  RP_ID: string;
  INVITE_ENABLED: string;
}

export type Caller = {
  userId: string;
  role: "super_admin" | "admin" | "user";
};

export type AppContext = {
  Bindings: Env;
  Variables: {
    caller: Caller | null;
    sessionId: string | null;
  };
};
