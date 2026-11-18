// Runs the firewall and the mock vendor in one process for local dev.
// The AGENT always runs separately (npm run agent) and never loads a key.
await import("./server.ts");
await import("./seller.ts");
