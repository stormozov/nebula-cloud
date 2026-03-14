import { combineReducers, configureStore } from "@reduxjs/toolkit";
import {
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
import { userApi } from "@/entities/user";
import userReducer from "@/entities/user/model/slice";

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

const authPersistConfig = {
  key: "auth",
  storage: persistStorage,
  whitelist: ["accessToken", "refreshToken", "user", "isAuthenticated"],
};

const persistedUserReducer = persistReducer(authPersistConfig, userReducer);

const rootReducer = combineReducers({
  user: persistedUserReducer,
  file: fileReducer,
  [userApi.reducerPath]: userApi.reducer,
  [fileApi.reducerPath]: fileApi.reducer,
});

export const store = configureStore({
  reducer: rootReducer,
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        ignoredActions: [FLUSH, REHYDRATE, PAUSE, PERSIST, PURGE, REGISTER],
      },
    })
      .concat(userApi.middleware)
      .concat(fileApi.middleware),
});

export const persistor = persistStore(store);

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;
