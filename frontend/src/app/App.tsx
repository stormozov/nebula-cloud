import { Provider } from "react-redux";
import { RouterProvider } from "react-router";

import { routesConfig } from "./routes";
import { store } from "./store/store";

function App() {
  return (
    <Provider store={store}>
      <RouterProvider router={routesConfig} />
    </Provider>
  );
}

export default App;
