// Chinese Wall policy: 
// Objects are divided in so-called conflict-of-interest (COI) classes
// Users should never have access simultaneously to two different objects belonging to the same COI class. 
// Initially, users have access to all objects, but as soon as they access a specific object o, they lose access to all objects belonging to the same COI class as o.

class CWP {
    Set<User> users;
    Set<Object> objects;
    Set<Set<Object>> coiClasses;

    Map<User, Set<Object>> accessedObjects;

    void accessObject(User u, Object o)
        requires (u in users) && (o in objects) && not Exists{coiClass in coiClasses; (o in coiClass) && Exists{o2 in accessedObjects[u]; o2 in coiClass}};
    {
        accessedObjects[u][o] = true;
    }

    void removeAccess(User u, Object o) 
        requires (u in users) && (o in objects) && (o in accessedObjects[u]);
    {
        accessedObjects[u][o] = false;
    }
}