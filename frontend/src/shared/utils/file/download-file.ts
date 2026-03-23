/**
 * Triggers file download from blob URL.
 * Generic utility - works with ANY blob, not tied to specific API.
 *
 * @param blob - File blob data
 * @param filename - Desired filename for download
 * @returns Promise that resolves when download is triggered
 *
 * @example
 * const blob = await response.blob();
 * await downloadFile(blob, 'document.pdf');
 */
export const downloadFile = async (
  blob: Blob,
  filename: string,
): Promise<void> => {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");

  link.href = url;
  link.download = filename;
  link.style.display = "none";

  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);

  // Clean up blob URL after delay
  setTimeout(() => URL.revokeObjectURL(url), 100);
};
