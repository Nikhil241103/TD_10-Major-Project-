import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { authAPI } from "../services/api";
import "bootstrap/dist/css/bootstrap.min.css";
import "../styles/login.css";

const ForgotPassword = () => {
    const [identifier, setIdentifier] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [errorMessage, setErrorMessage] = useState("");
    const [successMessage, setSuccessMessage] = useState("");
    const [showResetForm, setShowResetForm] = useState(false);
    const [newPassword, setNewPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [token, setToken] = useState("");

    const navigate = useNavigate();

    const handleForgotPassword = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setErrorMessage("");
        setSuccessMessage("");

        try {
            const res = await authAPI.forgotPassword(identifier);
            if (res.data.success) {
                setSuccessMessage("Password reset instructions have been sent to your email");
                setToken(res.data.token); // In production, this would come from email link
                setShowResetForm(true);
            }
        } catch (err) {
            setErrorMessage(err.response?.data?.message || "An error occurred");
        } finally {
            setIsLoading(false);
        }
    };

    const handleResetPassword = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        setErrorMessage("");

        if (newPassword !== confirmPassword) {
            setErrorMessage("Passwords do not match");
            setIsLoading(false);
            return;
        }

        try {
            const res = await authAPI.resetPassword(token, newPassword);
            if (res.data.success) {
                setSuccessMessage("Password has been reset successfully");
                setTimeout(() => {
                    navigate("/");
                }, 2000);
            }
        } catch (err) {
            setErrorMessage(err.response?.data?.message || "An error occurred");
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="login-container">
            <div className="login-form">
                <h2>Forgot Password</h2>
                {errorMessage && <div className="alert alert-danger">{errorMessage}</div>}
                {successMessage && <div className="alert alert-success">{successMessage}</div>}

                {!showResetForm ? (
                    <form onSubmit={handleForgotPassword}>
                        <div className="form-floating mb-4">
                            <input
                                type="text"
                                className="form-control"
                                id="identifier"
                                placeholder="Email or Username"
                                value={identifier}
                                onChange={(e) => setIdentifier(e.target.value)}
                                required
                            />
                            <label htmlFor="identifier">
                                <i className="fas fa-envelope"></i> Email or Username
                            </label>
                            <div className="input-focus-effect"></div>
                        </div>

                        <button type="submit" className="btn btn-primary w-100" disabled={isLoading}>
                            {isLoading ? (
                                <span className="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
                            ) : (
                                'Reset Password'
                            )}
                        </button>
                    </form>
                ) : (
                    <form onSubmit={handleResetPassword}>
                        <div className="form-floating mb-4">
                            <input
                                type="password"
                                className="form-control"
                                id="newPassword"
                                placeholder="New Password"
                                value={newPassword}
                                onChange={(e) => setNewPassword(e.target.value)}
                                required
                            />
                            <label htmlFor="newPassword">
                                <i className="fas fa-lock"></i> New Password
                            </label>
                            <div className="input-focus-effect"></div>
                        </div>

                        <div className="form-floating mb-4">
                            <input
                                type="password"
                                className="form-control"
                                id="confirmPassword"
                                placeholder="Confirm Password"
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                required
                            />
                            <label htmlFor="confirmPassword">
                                <i className="fas fa-lock"></i> Confirm Password
                            </label>
                            <div className="input-focus-effect"></div>
                        </div>

                        <button type="submit" className="btn btn-primary w-100" disabled={isLoading}>
                            {isLoading ? (
                                <span className="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
                            ) : (
                                'Set New Password'
                            )}
                        </button>
                    </form>
                )}

                <div className="mt-3 text-center">
                    <button 
                        className="btn btn-link" 
                        onClick={() => navigate("/")}
                    >
                        Back to Login
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ForgotPassword; 