import "./Divider.scss";

/**
 * Props interface for the Divider component.
 */
interface DividerProps {
  gap?: number | string;
}

/**
 * A horizontal rule (divider) component with customizable vertical spacing.
 *
 * @example
 * <Hr gap={20} />
 *
 * @example
 * <Hr gap="1rem" />
 */
export function Divider({ gap = 0 }: DividerProps) {
  return <div className="hr" style={{ margin: `${gap} 0` }}></div>;
}
