// Discretionary Access Control (DAC)
class DAC {
    // State variables
    type Right = <User, Object, {read, write}>;
    Set<User> users = new Set();
    Set<Object> objects = new Set();
    Set<Right> rights = new Set();
    Map<Object, User> ownerOf = new Map();

    // Access checks
    void read(User u, Object obj) requires <u, obj, read> in rights; {}
    void write(User u, Object obj) requires <u, obj, write> in rights; {}

    // Actions that impact the protection state
    void addRight(User owner, Right <u, o, r>) requires (owner in users) && (u in users) && (o in objects) && (ownerOf[o] == owner); {
        rights[<u, o, r>] = true; // add <u,o,r> to the rights set
    }

    void deleteRight(User owner, Right <u, o, r>) requires (owner in users) && (u in users) && (o in objects) && (ownerOf[o] == owner); {
        rights[<u, o, r>] = false; // remove <u,o,r> from the rights set
    }

    void addObject(User u, Object o) requires (u in users) && (o not in objects); {
        objects[o] = true;
        ownerOf[o] = u;
    }

    void deleteObject(User u, Object o) requires (u in users) && (o in objects) && (ownerOf[o] == u); {
        objects[o] = false;
        ownerOf[o] = none;
        rights = rights \ {<u2, o2, r> in rights where o2 == o};
    }

    void addUser(User u1, User u2) requires (u2 not in users); {
        users[u2] = true;
    }

    // Extensions
    void transferOwnership(User u1, User u2, Object o) requires (u1 in users) && (u2 in users) && (ownerOf[o] == u1); {
        objectsOf[o] = u2;
    }

    // To delegate the right to grant access to a file, we also need to keep track of who granted a user access to a file,
    // so we can undo this operation if we decide to revoke the right to grant access of that user
    type Right = <User, Object, {read, write}, User>
    type DelegationRight = <User, Object>;
    Set<DelegationRight> delegationRights = new Set();

    // We also need to modify addRight and deleteRight:
    // the condition (ownerOf[o] == owner) is too strong and should be adapted to (<u1, o> in delegationRights or ownerOf[o] == u1)

    void addDelegationRight(User u1, User u2, Object o) requires (u1 in users) && (u2 in users) && (o in objects) && (ownerOf[o] == u1): {
        delegationRights[<u2, o>] = true;
    }

    void revokeDelagationRight(User u1, User u2, Object o) requires (u1 in users) && (u2 in users) && (o in objects) 
            && (ownerOf[o] == u1) && (<u2, o> in delegationRights); {
        delegationRights[<u2, o>] = false;
        rights = rights \ {<u3, o2, r, ur> in rights where (ur == u2 && o2 == o)};
    }

}