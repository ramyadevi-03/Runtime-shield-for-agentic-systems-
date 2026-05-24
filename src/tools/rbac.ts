import jwt from "jsonwebtoken";

export function getUserRoles(token: string): string[] {

    const decoded: any = jwt.decode(token);

    if (!decoded || !decoded.realm_access) {
        throw new Error("Invalid token");
    }

    return decoded.realm_access.roles || [];
}

export function checkRole(userRoles: string[], allowedRoles: string[]) {

    const allowed = userRoles.some(role =>
        allowedRoles.includes(role)
    );

    if (!allowed) {
        throw new Error("Unauthorized tool access");
    }
}