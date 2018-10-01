// Lattice-based Access Control (LBAC)
class LBAC {
    Set<User> users =  new Set();
    Map<User, Label> clearance = new Map(); // label of users

    Set<Object> objects = new Set();
    Map<Object, Label> objectLabel = new Map(); // label of objects
    Set<Session> sessions = new Set();
    Map<Session, Label> sessionLabel = new Map(); // label of sessions

    // no read up
    void read(Session s, Object o) requires (s in sessions) && (o in objects) && (objectLabel[o] <= sessionLabel[s]); {}

    // no write down
    void write(Session s, Object o) requires (s in sessions) && (o in objects) && (objectLabel[o] >= sessionLabel[s]); {}

    Session createSession(User u, Label l) 
        requires (u in users) && (l <= clearance[u]); 
    {
        s = new Session();
        sessions[s] = true;
        sessionLabel[s] = l;
    }

    void addObject(Session s, Object o, Label l) 
        requires (s in sessions) && (o not in objects) && (l >= sessionLabel[s]) 
    {
        objects[o] = true;
        objectLabel[o] = l;
    }
}