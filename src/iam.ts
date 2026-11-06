import { z } from "zod";

export const UserRoleSchema = z.enum(["admin", "auditor", "user"]);
export type UserRole = z.infer<typeof UserRoleSchema>;

export const TokenPayloadSchema = z.object({
  userId: z.string().uuid(),
  email: z.string().email(),
  role: UserRoleSchema,
  iat: z.number(),
  exp: z.number()
});
export type TokenPayload = z.infer<typeof TokenPayloadSchema>;

export const AccessPolicySchema = z.object({
  resource: z.string(),
  action: z.enum(["read", "write", "delete"]),
  allowedRoles: z.array(UserRoleSchema)
});
export type AccessPolicy = z.infer<typeof AccessPolicySchema>;

export class IAMSimulator {
  private activeTokens: Map<string, TokenPayload> = new Map();
  private policies: AccessPolicy[] = [];

  constructor() {
    this.initializeDefaultPolicies();
  }

  private initializeDefaultPolicies() {
    this.policies.push(
      { resource: "financial_reports", action: "read", allowedRoles: ["admin", "auditor"] },
      { resource: "financial_reports", action: "write", allowedRoles: ["admin"] },
      { resource: "user_management", action: "delete", allowedRoles: ["admin"] }
    );
  }

  issueToken(payload: Omit<TokenPayload, "iat" | "exp">, expiresInSeconds: number = 3600): string {
    const iat = Math.floor(Date.now() / 1000);
    const exp = iat + expiresInSeconds;
    const tokenData: TokenPayload = { ...payload, iat, exp };
    
    TokenPayloadSchema.parse(tokenData);
    
    const mockToken = "token_" + Buffer.from(JSON.stringify(tokenData)).toString("base64");
    this.activeTokens.set(mockToken, tokenData);
    return mockToken;
  }

  verifyToken(token: string): TokenPayload {
    if (!token || !token.startsWith("token_")) {
      throw new Error("Invalid token format");
    }
    const tokenData = this.activeTokens.get(token);
    if (!tokenData) {
      throw new Error("Token not found or revoked");
    }
    if (Math.floor(Date.now() / 1000) > tokenData.exp) {
      throw new Error("Token expired");
    }
    return TokenPayloadSchema.parse(tokenData);
  }

  authorize(token: string, resource: string, action: "read" | "write" | "delete"): boolean {
    try {
      const user = this.verifyToken(token);
      const policy = this.policies.find(p => p.resource === resource && p.action === action);
      if (!policy) return false;
      return policy.allowedRoles.includes(user.role);
    } catch {
      return false;
    }
  }
}
