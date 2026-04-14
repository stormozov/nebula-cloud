import { lazy, Suspense } from "react";

import { PageLoader } from "@/shared/ui";

/**
 * Interface for a Promise that resolves to a component.
 */
interface ILoaderPromise {
  default: React.ComponentType;
}

/**
 * Type for a function that returns a Promise that resolves to a component.
 */
type LoaderType = () => Promise<ILoaderPromise>;

/**
 * Asynchronous loading of a component using React.lazy and React.Suspense.
 *
 * @param {LoaderType} loader - A function that returns a Promise that resolves
 * to a component.
 */
export const lazyWithSuspense = (loader: LoaderType) => {
  const LazyComponent = lazy(loader);
  return (
    <Suspense fallback={<PageLoader />}>
      <LazyComponent />
    </Suspense>
  );
};
