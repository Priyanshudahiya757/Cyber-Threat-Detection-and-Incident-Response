/**
 * src/components/ui/Button.tsx
 *
 * Purpose:
 *   The one button component used everywhere. Variants map to the
 *   design token system in tailwind.config.ts — "primary" uses the blue
 *   accent (actions), "outline"/"ghost" for secondary actions, "danger"
 *   for destructive actions (uses severity.critical), matching the
 *   red/orange/green semantic palette the brief specifies.
 */
import { forwardRef, type ButtonHTMLAttributes } from "react";
import { Loader2 } from "lucide-react";
import { cn } from "@/lib/cn";

type Variant = "primary" | "outline" | "ghost" | "danger";
type Size = "sm" | "md" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  isLoading?: boolean;
}

const variantClasses: Record<Variant, string> = {
  primary:
    "bg-accent-blue text-white hover:bg-accent-blue-dim focus-visible:ring-accent-blue disabled:bg-accent-blue/40",
  outline:
    "border border-border text-text-primary hover:bg-base-700 hover:border-accent-cyan/40 disabled:opacity-40",
  ghost: "text-text-secondary hover:bg-base-700 hover:text-text-primary disabled:opacity-40",
  danger:
    "bg-severity-critical text-white hover:bg-severity-critical/85 focus-visible:ring-severity-critical disabled:bg-severity-critical/40",
};

const sizeClasses: Record<Size, string> = {
  sm: "h-8 px-3 text-xs gap-1.5",
  md: "h-10 px-4 text-sm gap-2",
  lg: "h-12 px-6 text-base gap-2",
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = "primary", size = "md", isLoading, disabled, className, children, ...props }, ref) => {
    return (
      <button
        ref={ref}
        disabled={disabled || isLoading}
        className={cn(
          "inline-flex items-center justify-center rounded-md font-medium transition-colors",
          "disabled:cursor-not-allowed",
          variantClasses[variant],
          sizeClasses[size],
          className
        )}
        {...props}
      >
        {isLoading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
        {children}
      </button>
    );
  }
);
Button.displayName = "Button";
