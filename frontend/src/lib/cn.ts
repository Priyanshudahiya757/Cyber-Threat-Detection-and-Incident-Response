/**
 * src/lib/cn.ts
 * Thin wrapper over clsx for conditional className composition.
 */
import { clsx, type ClassValue } from "clsx";

export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs);
}
