import { type RefObject, useEffect } from "react";

/**
 * Custom React hook that triggers a callback when a click occurs outside
 * the element referenced by the provided ref.
 *
 * @template T - The type of the HTML element, extending `HTMLElement`.
 *
 * @param {RefObject<T | null>} ref - A React ref object pointing to the element
 * to monitor for outside clicks.
 * @param {() => void} callback - The function to be called when a click event
 * occurs outside the referenced element.
 *
 * @example
 * const modalRef = useRef<HTMLDivElement>(null);
 * useClickOutside(modalRef, () => closeModal());
 *
 * return (
 *   <div ref={modalRef}>
 *     Modal content
 *   </div>
 * );
 */
export const useClickOutside = <T extends HTMLElement = HTMLElement>(
  ref: RefObject<T | null>,
  callback: () => void,
) => {
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        callback();
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [ref, callback]);
};
