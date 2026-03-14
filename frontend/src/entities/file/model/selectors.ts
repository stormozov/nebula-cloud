import type { RootState } from "@/app/store/store";

export const selectFileList = (state: RootState) => state.file.fileList;
export const selectSelectedFile = (state: RootState) => state.file.selectedFile;
export const selectIsLoading = (state: RootState) => state.file.isLoading;
export const selectIsUploading = (state: RootState) => state.file.isUploading;
export const selectUploadProgress = (state: RootState) =>
  state.file.uploadProgress;
export const selectFileError = (state: RootState) => state.file.error;

export const selectFileById = (id: number) => (state: RootState) =>
  state.file.fileList.find((file) => file.id === id) || null;

export const selectFilesCount = (state: RootState) =>
  state.file.fileList.length;

export const selectTotalStorage = (state: RootState) =>
  state.file.fileList.reduce((sum, file) => sum + file.size, 0);
