/** Service identity shared by health, MCP server info and logs. Version mirrors package.json. */
import pkg from "../../package.json" with { type: "json" };

export const SERVICE_NAME = "mailverdict";
export const SERVICE_VERSION: string = pkg.version;
