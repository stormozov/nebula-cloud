import { lazy, Suspense } from "react";

interface ILoaderPromise {
	default: React.ComponentType;
}

type LoaderType = () => Promise<ILoaderPromise>;

/**
 * Asynchronous loading of a component using React.lazy and React.Suspense.
 *
 * @param {LoaderType} loader - A function that returns a Promise that resolves
 * 	to a component.
 */
export const lazyWithSuspense = (loader: LoaderType) => {
	const LazyComponent = lazy(loader);
	return (
		<Suspense fallback={"loading"}>
			<LazyComponent />
		</Suspense>
	);
};
