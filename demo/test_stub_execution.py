from shield_sdk import ShieldStub

def main():
    print("--- Customer Chatbot Environment ---")
    
    # 1. Customer initializes the stub with their assigned Tenant ID
    # This requires ZERO knowledge of MCP protocol from the customer
    stub = ShieldStub(tenant_id="customer-delta-99")
    
    # 2. Customer's chatbot decides it needs to read a file
    # It just calls the stub, passing an optional SSO token
    print("\n[Chatbot] Requesting to read a sensitive file...")
    
    response = stub.call_tool(
        tool_name="read_file",
        args={"path": "C:/Windows/System32/drivers/etc/hosts"},
        sso_token="eyJ_broad_user_token_abc123"
    )
    
    print("\n[Chatbot] Received Response State:", response)
    
    # Conceptually, the Bridge now does:
    # 1. Verifies 'eyJ_broad_user_token_abc123' via Keycloak JWKS.
    # 2. Sees 'read_file' requires 'tool:read_file' scope.
    # 3. Performs Token Exchange for a 60s JIT token.
    # 4. Passes 'jit_access_token_123_filesystem' to the jail.
    # 5. Even if the jail is hacked, the attacker only has a 60s, 
    #    single-scope token, not the user's broad master token.

if __name__ == "__main__":
    main()
