import { Routes, Route } from "react-router-dom";
import Login from "./pages/Login";
import PartnerList from "./pages/PartnerList";
import PartnerNew from "./pages/PartnerNew";
import PartnerDetail from "./pages/PartnerDetail";

export default function App() {
  return (
    <Routes>
      <Route path="/admin/login" element={<Login />} />
      <Route path="/admin" element={<PartnerList />} />
      <Route path="/admin/new" element={<PartnerNew />} />
      <Route path="/admin/:slug" element={<PartnerDetail />} />
    </Routes>
  );
}
