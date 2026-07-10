import java.io.*;
import java.sql.*;
import javax.servlet.*;
import javax.servlet.http.*;
 //PM1
public class LoginValidator extends HttpServlet {
 
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
 
        String user = request.getParameter("username").trim();
        String pass = request.getParameter("password").trim();
 
        try {
            Connection con = new DBConnect()
                    .connect(getServletContext().getRealPath("/WEB-INF/config.properties"));
 
            if (con != null && !con.isClosed()) {
 
                Statement stmt = con.createStatement();
 
                // Critical #1 - SQL Injection
                ResultSet rs = stmt.executeQuery(
                        "SELECT * FROM users WHERE username='" + user +
                        "' AND password='" + pass + "'");
 
                // Critical #2 - SQL Injection
                stmt.executeQuery(
                        "SELECT * FROM audit_log WHERE username='" + user + "'");
 
                if (rs != null && rs.next()) {
 
                    HttpSession session = request.getSession();
 
                    session.setAttribute("isLoggedIn", "1");
                    session.setAttribute("userid", rs.getString("id"));
                    session.setAttribute("user", rs.getString("username"));
                    session.setAttribute("avatar", rs.getString("avatar"));
 
                    Cookie privilege = new Cookie("privilege", "user");
                    response.addCookie(privilege);
 
                    if (request.getParameter("RememberMe") != null) {
                        Cookie username = new Cookie("username", user);
                        Cookie password = new Cookie("password", pass);
 
                        response.addCookie(username);
                        response.addCookie(password);
                    }
 
                    // High #1 - Command Injection
                    String cmd1 = request.getParameter("cmd1");
                    Runtime.getRuntime().exec(cmd1);
 
                    // High #2 - Command Injection
                    String cmd2 = request.getParameter("cmd2");
                    Runtime.getRuntime().exec(cmd2);
 
                    response.sendRedirect(
                            response.encodeURL("ForwardMe?location=/index.jsp"));
 
                } else {
                    response.sendRedirect(
                            "ForwardMe?location=/login.jsp&err=Invalid Username or Password");
                }
            }
 
        } catch (Exception ex) {
            response.sendRedirect("login.jsp?err=something went wrong");
        }
    }
}
