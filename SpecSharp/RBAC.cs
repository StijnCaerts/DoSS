// Role-based Access Control
// extended with static constraints and dynamic constraints on roles
class RBAC {
    Set<User> users;
    Set<Role> roles;
    Set<Permission> permissions;
    Map<Role, Set<Permission>> rolePermissions;
    Map<User, Set<Role>> userRoles;

    Set<Session> sessions;
    Map<Session, Set<Role>> sessionRoles;
    Map<User, Set<Session>> userSessions;

    Set<Set<Role>> incompatibleSessionRoles;
    Set<Set<Role>> incompatibleUserRoles;

    // to have access, there exists a role associated with this session that contains the permission
    void accessCheck(Session s, Permission p) 
        requires (s in sessions) && (p in permissions) && Exists{r in sessionRoles[s]; p in rolePermissions[r]};
    {}

    void createSession(User u, Set<Role> roles) 
        requires (u in users) && (roles <= userRoles[u]) && not Exists{rs in incompatibleSessionRoles; rs <= roles};
    {
        Session s = new Session();
        sessions[s] = true;
        sessionRoles[s] = roles;
        userSessions[u][s] = true;
    }

    void dropRole(User u, Session s, Role r) 
        requires (u in users) && (s in sessions) && (s in userSessions[u]) && (r in roles) && (r in sessionRoles[s]);
    {
        sessionRoles[s][r] = false;
    }

    // there doesn't exist a set of incompatible user roles such that it is a subset of (userRoles UNION {r})
    void addUserRole(User u, Role r)
        requires (u in users) && (r in roles) && not Exists{rs in incompatibleUserRoles; rs <= (userRoles[u] + {r})};
    {
        userRoles[s][r] = true;
    }
}