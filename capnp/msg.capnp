@0x87823e4e57e9dc81;

struct Msg {
  # id @0 :UInt32;
  # name @1 :Text;
#   email @2 :Text;
#   phones @3 :List(PhoneNumber);
#
#   struct PhoneNumber {
#     number @0 :Text;
#     type @1 :Type;
#
#     enum Type {
#       mobile @0;
#       home @1;
#       work @2;
#     }
#   }
#
  union {
    syn:group{
      id @0:UInt32;
    }
    ack:group{
      pk @1:Data;
    }
  }
#     unemployed @4 :Void;
#     employer @5 :Text;
#     school @6 :Text;
#     selfEmployed @7 :Void;
#     # We assume that a person is only one of these.
#   }
}

# struct AddressBook {
#   people @0 :List(Person);
# }
