import "./Divider.scss";

/**
 * Props interface for the Divider component.
 */
interface DividerProps {
  /** Vertical spacing between the divider and the adjacent elements. */
  gap?: number | string;
}

/**
 * A horizontal rule (divider) component with customizable vertical spacing.
 *
 * @example
 * <Divider gap={20} />
 *
 * @example
 * <Divider gap="1rem" />
 */
export function Divider({ gap = 0 }: DividerProps) {
  return (
    <hr className="divider" style={{ marginTop: gap, marginBottom: gap }}></hr>
  );
}
