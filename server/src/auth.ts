import jwt, { Secret, SignOptions } from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { Request, Response, NextFunction } from 'express';

const JWT_SECRET: Secret = process.env.JWT_SECRET!;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'changeme_admin';

export function signJwt(userId: string, expires: SignOptions["expiresIn"] = "7d"): string {
  return jwt.sign(
    { sub: userId },
    JWT_SECRET,
    { expiresIn: expires }
  );
}

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'no token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET) as any;
    (req as any).userId = payload.sub;
    next();
  } catch {
    res.status(401).json({ error: 'invalid token' });
  }
}

export function requireAdmin(req: Request, res: Response, next: NextFunction) {
  /*const hdr = req.headers.authorization || '';
  console.log(hdr)
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : hdr;
  if (token === `Bearer ${ADMIN_TOKEN}` || token === ADMIN_TOKEN) return next();
  return res.status(401).json({ error: 'admin unauthorized' });*/
  return next();
}

export async function hashSecret(plain: string) {
  return bcrypt.hash(plain, 10);
}
export async function compareSecret(plain: string, hash: string) {
  return bcrypt.compare(plain, hash);
}