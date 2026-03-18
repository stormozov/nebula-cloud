import { combineReducers, configureStore } from "@reduxjs/toolkit";
import {
  createTransform,
  FLUSH,
  PAUSE,
  PERSIST,
  PURGE,
  persistReducer,
  persistStore,
  REGISTER,
  REHYDRATE,
} from "redux-persist";

import { fileApi } from "@/entities/file";
import fileReducer from "@/entities/file/model/slice";
import type {
  IUploadFileSerialized,
  IUploadState,
} from "@/entities/file-upload";
import fileUploadReducer from "@/entities/file-upload/model/slice";
import { userApi } from "@/entities/user";
import userReducer from "@/entities/user/model/slice";

// =============================================================================
// PERSIST STORAGE
// =============================================================================

const persistStorage = {
  getItem: (key: string): Promise<string | null> => {
    const value = localStorage.getItem(key);
    return Promise.resolve(value);
  },
  setItem: (key: string, value: string): Promise<void> => {
    localStorage.setItem(key, value);
    return Promise.resolve();
  },
  removeItem: (key: string): Promise<void> => {
    localStorage.removeItem(key);
    return Promise.resolve();
  },
};

// =============================================================================
// PERSIST TRANSFORMS
// =============================================================================

/**
 * Transform for upload queue persistence.
 *
 * Serializes queue (removes File objects) and marks interrupted uploads
 * for reupload.
 */
const uploadQueueTransform = createTransform(
  // Serialize: State → LocalStorage
  (inboundState: IUploadState) => {
    const serializedQueue: IUploadFileSerialized[] = inboundState.queue.map(
      (item) => ({
        id: item.id,
        file: {
          name: item.file.name,
          size: item.file.size,
          type: item.file.type,
          lastModified: item.file.lastModified,
          comment: item.file.comment,
        },
        progress: item.status === "success" ? item.progress : 0,
        status: item.status === "uploading" ? "pending" : item.status,
        error: item.error,
        uploadedFileId: item.uploadedFileId,
        startedAt: item.startedAt,
        completedAt: item.completedAt,
        needsReupload: item.status === "uploading" || item.status === "pending",
      }),
    );

    return {
      ...inboundState,
      queue: serializedQueue,
      activeUploadId: null, // Reset active upload on save
    };
  },
  // Deserialize: LocalStorage → State
  (outboundState: IUploadState) => {
    // Mark pending uploads for reupload
    const queue = outboundState.queue.map((item) => ({
      ...item,
      needsReupload: item.status === "pending",
    }));

    // Find first pending file to start
    const firstPending = queue.find((i) => i.status === "pending");

    return {
      ...outboundState,
      queue,
      activeUploadId: firstPending ? firstPending.id : null,
      isQueueCompleted: false, // Reset on rehydration
    };
  },
  { whitelist: ["fileUpload"] },
);

// =============================================================================
// PERSIST CONFIGS
// =============================================================================

const authPersistConfig = {
  key: "auth",
  storage: persistStorage,
  whitelist: ["accessToken", "refreshToken", "user", "isAuthenticated"],
};

// Persist config for file upload queue
const uploadPersistConfig = {
  key: "upload",
  storage: persistStorage,
  transforms: [uploadQueueTransform],
  whitelist: ["totalUploaded", "totalFailed"],
};

const persistedUserReducer = persistReducer(authPersistConfig, userReducer);
const persistedUploadReducer = persistReducer(
  uploadPersistConfig,
  fileUploadReducer,
);

// =============================================================================
// STORE
// =============================================================================

const rootReducer = combineReducers({
  user: persistedUserReducer,
  file: fileReducer,
  fileUpload: persistedUploadReducer,
  [userApi.reducerPath]: userApi.reducer,
  [fileApi.reducerPath]: fileApi.reducer,
});

export const store = configureStore({
  reducer: rootReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        // Игнорируем стандартные действия redux-persist
        ignoredActions: [
          FLUSH,
          REHYDRATE,
          PAUSE,
          PERSIST,
          PURGE,
          REGISTER,
          // 🔧 Игнорируем экшены file-upload, которые содержат File объекты
          "fileUpload/addFiles",
        ],
        // 🔧 Игнорируем путь к файлам в экшенах
        ignoredActionPaths: ["payload.files", "payload.file"],
        // 🔧 Игнорируем очередь в state (там хранятся метаданные + File объекты)
        ignoredPaths: ["fileUpload.queue"],
      },
    })
      .concat(userApi.middleware)
      .concat(fileApi.middleware),
});

// =============================================================================
// EXPORTS
// =============================================================================

export const persistor = persistStore(store);

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
