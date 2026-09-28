import { RELEASE } from "./install-layout.ts";

/** Version of the source tree; must equal the root package.json version (checked by the release build). */
export const SOURCE_VERSION = "0.1.0";

/** Version of this CLI: the release build's version, or the source version in a dev checkout. */
export const CLI_VERSION: string = RELEASE?.version ?? SOURCE_VERSION;
