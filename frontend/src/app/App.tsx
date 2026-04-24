import { Provider } from "react-redux";
import { RouterProvider } from "react-router";

import { ThemeProvider } from "./providers/ThemeContext";
import { routesConfig } from "./routes";
import { store } from "./store/store";

function App() {
  return (
    <Provider store={store}>
      <ThemeProvider>
        <RouterProvider router={routesConfig} />
      </ThemeProvider>
    </Provider>
  );
}

export default App;
