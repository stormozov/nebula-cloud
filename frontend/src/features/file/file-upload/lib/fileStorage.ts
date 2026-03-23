/**
 * In-memory storage for File objects.
 *
 * @example
 * fileStorage.set(uploadId, file);
 * const file = fileStorage.get(uploadId);
 * fileStorage.remove(uploadId);
 */
class FileStorage {
  private files: Map<string, File> = new Map();

  /**
   * Store a File object by upload ID.
   */
  set(id: string, file: File): void {
    this.files.set(id, file);
  }

  /**
   * Retrieve a File object by upload ID.
   */
  get(id: string): File | undefined {
    return this.files.get(id);
  }

  /**
   * Remove a File object by upload ID.
   */
  remove(id: string): void {
    this.files.delete(id);
  }

  /**
   * Clear all stored File objects.
   */
  clear(): void {
    this.files.clear();
  }

  /**
   * Get count of stored files.
   */
  get size(): number {
    return this.files.size;
  }
}

export const fileStorage = new FileStorage();
