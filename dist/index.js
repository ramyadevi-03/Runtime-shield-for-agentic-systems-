import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { registerTools } from "./tools/tools.js";
import { verifySpiffeIdentity } from "./tools/spiffeAuth.js";
import dotenv from "dotenv";
import path from "node:path";
import { fileURLToPath } from 'node:url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const envPath = path.resolve(__dirname, '../.env');
dotenv.config({ path: envPath });
if (!process.env.KEYCLOAK_URL) {
    // If loading failed, try to debug why
    console.error("Error: KEYCLOAK_URL not found in environment variables.");
    console.error("Make sure you are running the server from the project root.");
    console.error("Current directory:", process.cwd());
}
// Create an MCP server instance
const server = new McpServer({
    name: "Secure-Runtime-Shield",
    version: "1.0.0",
});
// Register the Keycloak tools
registerTools(server);
// Connect via Stdio
async function main() {
    console.error("🔐 Initializing SPIFFE Workload Attestation...");
    await verifySpiffeIdentity().catch(err => console.error("⚠️ SPIFFE Error:", err));
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Keycloak MCP Server running on stdio");
}
main().catch((error) => {
    console.error("Fatal error in main():", error);
    process.exit(1);
});
