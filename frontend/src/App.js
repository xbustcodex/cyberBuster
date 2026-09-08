import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "sonner";
import { AuthProvider, useAuth } from "@/context/AuthContext";
import { Layout } from "@/components/Layout";
import Login from "@/pages/Login";
import FleetOverview from "@/pages/FleetOverview";
import WorkstationDetail from "@/pages/WorkstationDetail";
import CveAlerts from "@/pages/CveAlerts";
import ProfileDistribution from "@/pages/ProfileDistribution";
import SignedReleases from "@/pages/SignedReleases";
import EnrollWorkstation from "@/pages/Enroll";
import Plugins from "@/pages/Plugins";
import SigmaImport from "@/pages/SigmaImport";

function Protected({ children }) {
  const { user } = useAuth();
  if (user === null) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#1a1b26]">
        <div className="font-mono text-xs text-[#565f89]">sec-master:~$ verifying session…<span className="cursor" /></div>
      </div>
    );
  }
  if (user === false) return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Toaster
          position="bottom-right"
          toastOptions={{
            style: {
              background: "#15161e",
              color: "#c0caf5",
              border: "1px solid #3b4261",
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "12px",
            },
          }}
        />
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<Navigate to="/fleet" replace />} />
          <Route path="/fleet" element={<Protected><FleetOverview /></Protected>} />
          <Route path="/fleet/:id" element={<Protected><WorkstationDetail /></Protected>} />
          <Route path="/cves" element={<Protected><CveAlerts /></Protected>} />
          <Route path="/profiles" element={<Protected><ProfileDistribution /></Protected>} />
          <Route path="/releases" element={<Protected><SignedReleases /></Protected>} />
          <Route path="/plugins" element={<Protected><Plugins /></Protected>} />
          <Route path="/sigma" element={<Protected><SigmaImport /></Protected>} />
          <Route path="/enroll" element={<Protected><EnrollWorkstation /></Protected>} />
          <Route path="*" element={<Navigate to="/fleet" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
