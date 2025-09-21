"use client"

import { Navigate, Outlet } from "react-router-dom"
import { useAuth } from "../Auth/AuthContext"
import Layout from "../components/Layout/AppContainer"

const PrivateRoute = () => {
  const { isAuthenticated } = useAuth()

  return isAuthenticated ? (
    <Layout>
      <Outlet />
    </Layout>
  ) : (
    <Navigate to="/login" replace />
  )
}

export default PrivateRoute
