import { setupServer } from "msw/node";

import { fileApiHandlers } from "./fileApiHandlers";
import { userApiHandlers } from "./userApiHandlers";

export const server = setupServer(...userApiHandlers, ...fileApiHandlers);
