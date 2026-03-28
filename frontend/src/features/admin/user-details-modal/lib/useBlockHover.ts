import { useState } from "react";

/**
 * Interface for the `useBlockHover` hook return values.
 */
interface IUseBlockHoverReturns {
  /** The title of the currently hovered block, or null if none is hovered. */
  hoveredBlock: string | null;
  /** Function to set the hovered block title. */
  setHoveredBlock: React.Dispatch<React.SetStateAction<string | null>>;
  /** Function to set the hovered block title. */
  handleMouseEnter: (blockTitle: string) => void;
  /** Function to handle mouse leaving a block. */
  handleMouseLeave: () => void;
  /** Function to check if a block is currently hovered. */
  isHovered: (blockTitle: string) => boolean;
}

/**
 * Custom hook for managing hover state on UI blocks.
 *
 * Tracks which block is currently being hovered over, allowing for interactive
 * visual feedback such as highlighting or displaying additional controls.
 */
export const useBlockHover = (): IUseBlockHoverReturns => {
  const [hoveredBlock, setHoveredBlock] = useState<string | null>(null);

  const handleMouseEnter = (blockTitle: string) => setHoveredBlock(blockTitle);
  const handleMouseLeave = () => setHoveredBlock(null);
  const isHovered = (blockTitle: string) => hoveredBlock === blockTitle;

  return {
    hoveredBlock,
    setHoveredBlock,
    handleMouseEnter,
    handleMouseLeave,
    isHovered,
  };
};
