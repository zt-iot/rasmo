---- MODULE sc ----
EXTENDS Naturals, Sequences, TLC, FiniteSets
CONSTANTS Devices, IPs, NULL, MaxFails, MaxUnblocks, AdminProc
ASSUME /\ IPs # {}
    /\ NULL \notin IPs
    /\ MaxFails \in Nat
    /\ MaxUnblocks \in Nat
    /\ Devices # {} 
    /\ AdminProc \notin Devices

\* NULL and AdminProc are model values
\* IPs, Devices are a symmetric set of model values

\* DeviceSymmetry == Permutations(Devices)
\* IPsSymmetry == Permutations(IPs)
\* Symmetry == DeviceSymmetry \cup IPsSymmetry

ZabbixRecvs == {[type |-> "recv", dev |-> d]: d \in Devices}
ZabbixSyncs == {[type |-> "sync", dev |-> d]: d \in Devices}

DeviceOf(p) == p.dev
RecvOf(d) == [type |-> "recv", dev |-> d]
SyncOf(d) == [type |-> "sync", dev |-> d]

SyncOfRecv(r) == [type |-> "sync", dev |-> DeviceOf(r)]

DeviceStateType == {"NORMAL", "FAIL"}
MsgType == [ip: IPs, xid: Nat]

\* Entry type for device
LocalEntryType == [ip: IPs, committed: BOOLEAN, sync: BOOLEAN, unblocked: BOOLEAN]

\* Server Type: Maintains a blocklist of IPs with timestamps
ServerDataType == [ip: IPs, unblocked: BOOLEAN, xid: Nat]
ServerDataTypeNULL == [ip: IPs \cup {NULL}, unblocked: BOOLEAN, xid: Nat]

\* for concurrent DB transactions writing to the GlobalBlocklist
\* in implementation, we limit the xid_max to the smallest in-flight transaction's xid to avoid data loss
\* addressing the assignment-order /= commit-order race problem;
\* in PostgreSQL, the xmin of the in-progress transaction can be obtained by "pg_snapshot_xmin(pg_current_snapshot())"
Max(s) == IF s = {} THEN 0 ELSE (CHOOSE e \in s: \A o \in s: o <= e)
NewestXid(S) == IF S = {} THEN 0 ELSE (CHOOSE e \in S: \A o \in S: o.xid <= e.xid).xid
EntryRange(S, xid_min, xid_max) == {r \in S: r.xid > xid_min /\ r.xid <= xid_max } \* empty set if S is empty

(*--algorithm sc {

variables
    \* device variables
    DeviceState = [d \in Devices |-> "NORMAL"], \* initial device state
    SyncBuf = [d \in Devices |-> {}], \* Device Sync buffer: set of [ip: IPs, unblocked: BOOLEAN, xid: Nat]
    LocalLog = [d \in Devices |-> {}], \* Local set of type [ip: IPs, committed: BOOLEAN, sync: BOOLEAN, unblocked: BOOLEAN]
    LocalBlocklist = [d \in Devices |-> {}], \* Local set of blocked IPs
    \* zabbix variables
    SenderBuf = [d \in ZabbixRecvs |-> {}], \* Zabbix Recv buffer: set of [ip: IPs, xid: Nat]
    Cursor = [d \in ZabbixSyncs |-> 0], \* Zabbix SyncAck item: Max(xids)
    GlobalBlocklist = {}; \* Zabbix global blocklist state: [ip: IPs, unblocked: BOOLEAN, xid: Nat]

\* send msg to the Zabbix server: [ip: IPs, xid: Nat]
fair process (LocalDev \in Devices)
    variables
    	NumFails = 0, \* number of failures per device to track if failure budget is exhausted
        CurIP = NULL,
    	LastSyncedXid = 0; \* the most recent xid the device has synchronized: kv-store on permanent storage to survive crash
{
    dev_op:
        while (DeviceState[self] = "NORMAL") {
            \* detect and block IP
            either {
                \* disable detect branch if all the IPs are seen; then or(s) will be picked;
                \* also, modeling crash here is meaningless -> just re-pick an address
                with (i \in {ip \in IPs: ~\E e \in LocalLog[self]: e.ip = ip}) {
                    CurIP := i;
                    LocalLog := [LocalLog EXCEPT ![self] = @ \cup {[ip|->CurIP, committed|->FALSE, sync|->FALSE, unblocked|->FALSE]}];

                    (* \* no reblock
                    if (\E e \in LocalLog[self]: e.ip = CurIP /\ e.unblocked = TRUE) {
                        \* remove the existing unblocked entry and add a new entry to reblock
                        with (e \in {entry \in LocalLog[self]: entry.ip = CurIP /\ entry.unblocked = TRUE}) {
                            LocalLog := [LocalLog EXCEPT ![self] = (@ \ {e})
                                                                    \cup
                                                                    {[ip|->CurIP, committed|->FALSE, sync|->FALSE, unblocked|->FALSE]}];
                        };
                    }
                    else {
                        LocalLog := [LocalLog EXCEPT ![self] = @ \cup {[ip|->CurIP, committed|->FALSE, sync|->FALSE, unblocked|->FALSE]}];
                    };
                    *)
                };
                commit:
                \* Block the IP (commit)
                either {
                    LocalBlocklist := [LocalBlocklist EXCEPT ![self] = @ \cup {CurIP}];
                    with (entry \in {e \in LocalLog[self]: e.ip = CurIP}) {
                        LocalLog := [LocalLog EXCEPT ![self] = (@ \ {entry}) \cup {[entry EXCEPT !.committed = TRUE]}];
                    };
                }
                or {
                    await NumFails < MaxFails;
                    NumFails := NumFails + 1;
                    goto fail;
                };
                send:
                \* append msg to the zabbix receiver buffer
                either {
                    SenderBuf := [SenderBuf EXCEPT ![RecvOf(self)] = @ \cup {[ip|->CurIP, xid |-> LastSyncedXid]}];
                    CurIP := NULL;
                }
                or {
                    await NumFails < MaxFails;
                    NumFails := NumFails + 1;
                    goto fail;
                };
			} \* either
            or {
                await SyncBuf[self] /= {};
                sync:
                either {
                    \* choose latest op per IP in the sync queue;
                    \* do sync atomically since the device receives a batch of updates to reduce state space
                        \* update LocalLog for sync in batch
                    with (LatestOPs = {entry \in SyncBuf[self]: \A entry2 \in SyncBuf[self]: entry2.ip = entry.ip => entry2.xid <= entry.xid}) {
                        LocalBlocklist := [LocalBlocklist EXCEPT ![self] = LET BlockIPs == {e.ip: e \in {entry \in LatestOPs: entry.unblocked = FALSE}}
                                                                            UnblockIPs == {e.ip: e \in {entry \in LatestOPs: entry.unblocked = TRUE}}
                                                                            IN (LocalBlocklist[self] \ UnblockIPs) \cup BlockIPs];
                        LocalLog := [LocalLog EXCEPT ![self] =  LET OldLog == @
                                                                    NewEntry == {entry \in LatestOPs: ~\E e \in OldLog: e.ip = entry.ip}
                                                                    SyncIPs == {entry.ip: entry \in LatestOPs}
                                                                IN
                                                                { IF e.ip \in SyncIPs
                                                                THEN [e EXCEPT  !.committed = TRUE,
                                                                                !.sync = TRUE,
                                                                                !.unblocked = (CHOOSE entry \in LatestOPs: entry.ip = e.ip).unblocked]
                                                                ELSE e: e \in OldLog }
                                                                \cup
                                                                {[ip |-> s.ip, committed |-> TRUE, sync |-> TRUE, unblocked |-> s.unblocked]: s \in NewEntry}
                                                                ];
                        LastSyncedXid := NewestXid(LatestOPs); \* send this to cursor if sync succeeds
                        SyncBuf := [SyncBuf EXCEPT ![self] = {}];
                    };
                }
                or {
                    await NumFails < MaxFails;
                    NumFails := NumFails + 1;
                    goto fail;
                };

                \* if all the entries are successfully committed
                sync_ack:
                either {
                    Cursor := [Cursor EXCEPT ![SyncOf(self)] = IF LastSyncedXid > @ THEN LastSyncedXid ELSE @];
                }
                or {
                    await NumFails < MaxFails;
                    NumFails := NumFails + 1;
                    goto fail;
                };
            };  \* zabbix sync and sync_ack
        }; \* while (NORMAL)

    fail:
        \* LocalLog persist between reboot
        DeviceState := [DeviceState EXCEPT ![self] = "FAIL"];

    recover:
        \* assume that device subscribe to /sync data only after recovery is completed
        \* maintain the order between recovery and receiving sync messages
        \* atomic recovery: 

        \* recover local blocklist from local log
        with (AllEntries = LocalLog[self],
            Unack = {e \in AllEntries: e.sync = FALSE /\ e.unblocked = FALSE},
            Blocked = {e \in AllEntries: e.unblocked = FALSE}) {
            
            LocalBlocklist := [LocalBlocklist EXCEPT ![self] = {e.ip: e \in Blocked}];
            LocalLog := [LocalLog EXCEPT ![self] = {IF e.committed = FALSE THEN [e EXCEPT !.committed = TRUE] ELSE e: e \in @}];
            \* send unsynced entries again
            SenderBuf := [SenderBuf EXCEPT ![RecvOf(self)] = @ \cup {[ip |-> e.ip, xid |-> LastSyncedXid]: e \in Unack}];
        };

        \* reset all the device volatile data structures; LocalLog and LastSyncedXid must be persistent on disk
        SyncBuf := [SyncBuf EXCEPT ![self] = {}];
        CurIP := NULL;

        \* set device states to normal and go back to dev_op
        DeviceState := [DeviceState EXCEPT ![self] = "NORMAL"];
        goto dev_op;
}

\* Data receiver for each host (block operations only)
\* Conflict resolution policy for IPs:
\* 1. if IP not in GlobalBlocklist, add to blocklist
\* 2. if IP in GlobalBlocklist with unblocked = FALSE, ignore the insertion
\* 3. if IP in GlobalBlocklist with unblocked = TRUE, update the record only if the block.xid >= unblocked.xid
\*    (i.e., the unblock has been synced to the device);
\*    addressing the case when a device crashed before sync, or stale block messages stuck in receiver,
\*    if such IP addresses were blocked by other devices then unblocked by admin during the meantime,
\*    then the stale block will cause the IP to be blocked again; such stale blocks should be dropped.
\* Each loop is a transaction to update the global blocklist by the arrived data batch
fair process (zabbix_r \in ZabbixRecvs) {
    receive:
    while (TRUE) {
        \* when sender queue has data, trigger fires -> execute action script
        await SenderBuf[self] /= {};

        with (CurXid = NewestXid(GlobalBlocklist),
            StaleBlockRemoved = {e \in SenderBuf[self]: ~(\E entry \in GlobalBlocklist:
                                                 /\ entry.unblocked = TRUE 
                                                 /\ entry.ip = e.ip 
                                                 /\ entry.xid > e.xid)},
            BatchIP = {e.ip: e \in StaleBlockRemoved},
            BlockedIP = {e.ip: e \in {entry \in GlobalBlocklist: entry.unblocked = FALSE}},
            ToAdd = BatchIP \ BlockedIP,
            ToRemove = {e \in GlobalBlocklist: e.unblocked = TRUE /\ (e.ip \in ToAdd)}) {

            GlobalBlocklist :=  (GlobalBlocklist \ ToRemove)
                            \cup
                            { [ip |-> ip, unblocked |-> FALSE, xid |-> CurXid + 1]: ip \in ToAdd};
        };
        SenderBuf := [SenderBuf EXCEPT ![self] = {}]; \* consume data from sender buffer
    }; \* while (TRUE)
}

\* trigger evaluates when ODBC receives new data
fair process (zabbix_sync \in ZabbixSyncs)
{
    odbc:
    while (TRUE) {
        \* pulled the newest data /\ not equal to cursor
        \* NewestXid(GlobalBlocklist) is the newest xid committed to the GlobalBlocklist that
        \* is smaller than pg_snapshot_xmin(pg_current_snapshot()), the xmin of the current in-flight transaction
        with (latest = NewestXid(GlobalBlocklist)) {
            await DeviceState[DeviceOf(self)] = "NORMAL" /\ (latest /= Cursor[self]);
            \* put data on sync queue
            SyncBuf := [SyncBuf EXCEPT ![DeviceOf(self)] = @ \cup EntryRange(GlobalBlocklist,
                                                                        Cursor[self],
                                                                        latest)];
        };
    }; \* while (TRUE)
}

\* admin unblocks IPs
process (admin = AdminProc)
    variable
        NumUnblocks = 0; \* total number of unblocks
{
    unblock:
    while (NumUnblocks < MaxUnblocks) {
        with (AllowUnblock = { e \in GlobalBlocklist: e.unblocked = FALSE }) {
            await AllowUnblock /= {};

            with (entry \in AllowUnblock) {
                GlobalBlocklist := (GlobalBlocklist \ {entry})
                                \cup
                                {[entry EXCEPT !.unblocked = TRUE, !.xid = 1 + NewestXid(GlobalBlocklist)]};
                NumUnblocks := NumUnblocks + 1;
            };
        };
    };
}

}\* End of algorithm sc
*)
\* BEGIN TRANSLATION (chksum(pcal) = "f4561175" /\ chksum(tla) = "5224cd72")
VARIABLES DeviceState, SyncBuf, LocalLog, LocalBlocklist, SenderBuf, Cursor, 
          GlobalBlocklist, pc, NumFails, CurIP, LastSyncedXid, NumUnblocks

vars == << DeviceState, SyncBuf, LocalLog, LocalBlocklist, SenderBuf, Cursor, 
           GlobalBlocklist, pc, NumFails, CurIP, LastSyncedXid, NumUnblocks
        >>

ProcSet == (Devices) \cup (ZabbixRecvs) \cup (ZabbixSyncs) \cup {AdminProc}

Init == (* Global variables *)
        /\ DeviceState = [d \in Devices |-> "NORMAL"]
        /\ SyncBuf = [d \in Devices |-> {}]
        /\ LocalLog = [d \in Devices |-> {}]
        /\ LocalBlocklist = [d \in Devices |-> {}]
        /\ SenderBuf = [d \in ZabbixRecvs |-> {}]
        /\ Cursor = [d \in ZabbixSyncs |-> 0]
        /\ GlobalBlocklist = {}
        (* Process LocalDev *)
        /\ NumFails = [self \in Devices |-> 0]
        /\ CurIP = [self \in Devices |-> NULL]
        /\ LastSyncedXid = [self \in Devices |-> 0]
        (* Process admin *)
        /\ NumUnblocks = 0
        /\ pc = [self \in ProcSet |-> CASE self \in Devices -> "dev_op"
                                        [] self \in ZabbixRecvs -> "receive"
                                        [] self \in ZabbixSyncs -> "odbc"
                                        [] self = AdminProc -> "unblock"]

dev_op(self) == /\ pc[self] = "dev_op"
                /\ IF DeviceState[self] = "NORMAL"
                      THEN /\ \/ /\ \E i \in {ip \in IPs: ~\E e \in LocalLog[self]: e.ip = ip}:
                                      /\ CurIP' = [CurIP EXCEPT ![self] = i]
                                      /\ LocalLog' = [LocalLog EXCEPT ![self] = @ \cup {[ip|->CurIP'[self], committed|->FALSE, sync|->FALSE, unblocked|->FALSE]}]
                                 /\ pc' = [pc EXCEPT ![self] = "commit"]
                              \/ /\ SyncBuf[self] /= {}
                                 /\ pc' = [pc EXCEPT ![self] = "sync"]
                                 /\ UNCHANGED <<LocalLog, CurIP>>
                      ELSE /\ pc' = [pc EXCEPT ![self] = "fail"]
                           /\ UNCHANGED << LocalLog, CurIP >>
                /\ UNCHANGED << DeviceState, SyncBuf, LocalBlocklist, 
                                SenderBuf, Cursor, GlobalBlocklist, NumFails, 
                                LastSyncedXid, NumUnblocks >>

commit(self) == /\ pc[self] = "commit"
                /\ \/ /\ LocalBlocklist' = [LocalBlocklist EXCEPT ![self] = @ \cup {CurIP[self]}]
                      /\ \E entry \in {e \in LocalLog[self]: e.ip = CurIP[self]}:
                           LocalLog' = [LocalLog EXCEPT ![self] = (@ \ {entry}) \cup {[entry EXCEPT !.committed = TRUE]}]
                      /\ pc' = [pc EXCEPT ![self] = "send"]
                      /\ UNCHANGED NumFails
                   \/ /\ NumFails[self] < MaxFails
                      /\ NumFails' = [NumFails EXCEPT ![self] = NumFails[self] + 1]
                      /\ pc' = [pc EXCEPT ![self] = "fail"]
                      /\ UNCHANGED <<LocalLog, LocalBlocklist>>
                /\ UNCHANGED << DeviceState, SyncBuf, SenderBuf, Cursor, 
                                GlobalBlocklist, CurIP, LastSyncedXid, 
                                NumUnblocks >>

send(self) == /\ pc[self] = "send"
              /\ \/ /\ SenderBuf' = [SenderBuf EXCEPT ![RecvOf(self)] = @ \cup {[ip|->CurIP[self], xid |-> LastSyncedXid[self]]}]
                    /\ CurIP' = [CurIP EXCEPT ![self] = NULL]
                    /\ pc' = [pc EXCEPT ![self] = "dev_op"]
                    /\ UNCHANGED NumFails
                 \/ /\ NumFails[self] < MaxFails
                    /\ NumFails' = [NumFails EXCEPT ![self] = NumFails[self] + 1]
                    /\ pc' = [pc EXCEPT ![self] = "fail"]
                    /\ UNCHANGED <<SenderBuf, CurIP>>
              /\ UNCHANGED << DeviceState, SyncBuf, LocalLog, LocalBlocklist, 
                              Cursor, GlobalBlocklist, LastSyncedXid, 
                              NumUnblocks >>

sync(self) == /\ pc[self] = "sync"
              /\ \/ /\ LET LatestOPs == {entry \in SyncBuf[self]: \A entry2 \in SyncBuf[self]: entry2.ip = entry.ip => entry2.xid <= entry.xid} IN
                         /\ LocalBlocklist' = [LocalBlocklist EXCEPT ![self] = LET BlockIPs == {e.ip: e \in {entry \in LatestOPs: entry.unblocked = FALSE}}
                                                                                UnblockIPs == {e.ip: e \in {entry \in LatestOPs: entry.unblocked = TRUE}}
                                                                                IN (LocalBlocklist[self] \ UnblockIPs) \cup BlockIPs]
                         /\ LocalLog' = [LocalLog EXCEPT ![self] =  LET OldLog == @
                                                                        NewEntry == {entry \in LatestOPs: ~\E e \in OldLog: e.ip = entry.ip}
                                                                        SyncIPs == {entry.ip: entry \in LatestOPs}
                                                                    IN
                                                                    { IF e.ip \in SyncIPs
                                                                    THEN [e EXCEPT  !.committed = TRUE,
                                                                                    !.sync = TRUE,
                                                                                    !.unblocked = (CHOOSE entry \in LatestOPs: entry.ip = e.ip).unblocked]
                                                                    ELSE e: e \in OldLog }
                                                                    \cup
                                                                    {[ip |-> s.ip, committed |-> TRUE, sync |-> TRUE, unblocked |-> s.unblocked]: s \in NewEntry}
                                                                    ]
                         /\ LastSyncedXid' = [LastSyncedXid EXCEPT ![self] = NewestXid(LatestOPs)]
                         /\ SyncBuf' = [SyncBuf EXCEPT ![self] = {}]
                    /\ pc' = [pc EXCEPT ![self] = "sync_ack"]
                    /\ UNCHANGED NumFails
                 \/ /\ NumFails[self] < MaxFails
                    /\ NumFails' = [NumFails EXCEPT ![self] = NumFails[self] + 1]
                    /\ pc' = [pc EXCEPT ![self] = "fail"]
                    /\ UNCHANGED <<SyncBuf, LocalLog, LocalBlocklist, LastSyncedXid>>
              /\ UNCHANGED << DeviceState, SenderBuf, Cursor, GlobalBlocklist, 
                              CurIP, NumUnblocks >>

sync_ack(self) == /\ pc[self] = "sync_ack"
                  /\ \/ /\ Cursor' = [Cursor EXCEPT ![SyncOf(self)] = IF LastSyncedXid[self] > @ THEN LastSyncedXid[self] ELSE @]
                        /\ pc' = [pc EXCEPT ![self] = "dev_op"]
                        /\ UNCHANGED NumFails
                     \/ /\ NumFails[self] < MaxFails
                        /\ NumFails' = [NumFails EXCEPT ![self] = NumFails[self] + 1]
                        /\ pc' = [pc EXCEPT ![self] = "fail"]
                        /\ UNCHANGED Cursor
                  /\ UNCHANGED << DeviceState, SyncBuf, LocalLog, 
                                  LocalBlocklist, SenderBuf, GlobalBlocklist, 
                                  CurIP, LastSyncedXid, NumUnblocks >>

fail(self) == /\ pc[self] = "fail"
              /\ DeviceState' = [DeviceState EXCEPT ![self] = "FAIL"]
              /\ pc' = [pc EXCEPT ![self] = "recover"]
              /\ UNCHANGED << SyncBuf, LocalLog, LocalBlocklist, SenderBuf, 
                              Cursor, GlobalBlocklist, NumFails, CurIP, 
                              LastSyncedXid, NumUnblocks >>

recover(self) == /\ pc[self] = "recover"
                 /\ LET AllEntries == LocalLog[self] IN
                      LET Unack == {e \in AllEntries: e.sync = FALSE /\ e.unblocked = FALSE} IN
                        LET Blocked == {e \in AllEntries: e.unblocked = FALSE} IN
                          /\ LocalBlocklist' = [LocalBlocklist EXCEPT ![self] = {e.ip: e \in Blocked}]
                          /\ LocalLog' = [LocalLog EXCEPT ![self] = {IF e.committed = FALSE THEN [e EXCEPT !.committed = TRUE] ELSE e: e \in @}]
                          /\ SenderBuf' = [SenderBuf EXCEPT ![RecvOf(self)] = @ \cup {[ip |-> e.ip, xid |-> LastSyncedXid[self]]: e \in Unack}]
                 /\ SyncBuf' = [SyncBuf EXCEPT ![self] = {}]
                 /\ CurIP' = [CurIP EXCEPT ![self] = NULL]
                 /\ DeviceState' = [DeviceState EXCEPT ![self] = "NORMAL"]
                 /\ pc' = [pc EXCEPT ![self] = "dev_op"]
                 /\ UNCHANGED << Cursor, GlobalBlocklist, NumFails, 
                                 LastSyncedXid, NumUnblocks >>

LocalDev(self) == dev_op(self) \/ commit(self) \/ send(self) \/ sync(self)
                     \/ sync_ack(self) \/ fail(self) \/ recover(self)

receive(self) == /\ pc[self] = "receive"
                 /\ SenderBuf[self] /= {}
                 /\ LET CurXid == NewestXid(GlobalBlocklist) IN
                      LET StaleBlockRemoved == {e \in SenderBuf[self]: ~(\E entry \in GlobalBlocklist:
                                                                /\ entry.unblocked = TRUE
                                                                /\ entry.ip = e.ip
                                                                /\ entry.xid > e.xid)} IN
                        LET BatchIP == {e.ip: e \in StaleBlockRemoved} IN
                          LET BlockedIP == {e.ip: e \in {entry \in GlobalBlocklist: entry.unblocked = FALSE}} IN
                            LET ToAdd == BatchIP \ BlockedIP IN
                              LET ToRemove == {e \in GlobalBlocklist: e.unblocked = TRUE /\ (e.ip \in ToAdd)} IN
                                GlobalBlocklist' =     (GlobalBlocklist \ ToRemove)
                                                   \cup
                                                   { [ip |-> ip, unblocked |-> FALSE, xid |-> CurXid + 1]: ip \in ToAdd}
                 /\ SenderBuf' = [SenderBuf EXCEPT ![self] = {}]
                 /\ pc' = [pc EXCEPT ![self] = "receive"]
                 /\ UNCHANGED << DeviceState, SyncBuf, LocalLog, 
                                 LocalBlocklist, Cursor, NumFails, CurIP, 
                                 LastSyncedXid, NumUnblocks >>

zabbix_r(self) == receive(self)

odbc(self) == /\ pc[self] = "odbc"
              /\ LET latest == NewestXid(GlobalBlocklist) IN
                   /\ DeviceState[DeviceOf(self)] = "NORMAL" /\ (latest /= Cursor[self])
                   /\ SyncBuf' = [SyncBuf EXCEPT ![DeviceOf(self)] = @ \cup EntryRange(GlobalBlocklist,
                                                                                  Cursor[self],
                                                                                  latest)]
              /\ pc' = [pc EXCEPT ![self] = "odbc"]
              /\ UNCHANGED << DeviceState, LocalLog, LocalBlocklist, SenderBuf, 
                              Cursor, GlobalBlocklist, NumFails, CurIP, 
                              LastSyncedXid, NumUnblocks >>

zabbix_sync(self) == odbc(self)

unblock == /\ pc[AdminProc] = "unblock"
           /\ IF NumUnblocks < MaxUnblocks
                 THEN /\ LET AllowUnblock == { e \in GlobalBlocklist: e.unblocked = FALSE } IN
                           /\ AllowUnblock /= {}
                           /\ \E entry \in AllowUnblock:
                                /\ GlobalBlocklist' =    (GlobalBlocklist \ {entry})
                                                      \cup
                                                      {[entry EXCEPT !.unblocked = TRUE, !.xid = 1 + NewestXid(GlobalBlocklist)]}
                                /\ NumUnblocks' = NumUnblocks + 1
                      /\ pc' = [pc EXCEPT ![AdminProc] = "unblock"]
                 ELSE /\ pc' = [pc EXCEPT ![AdminProc] = "Done"]
                      /\ UNCHANGED << GlobalBlocklist, NumUnblocks >>
           /\ UNCHANGED << DeviceState, SyncBuf, LocalLog, LocalBlocklist, 
                           SenderBuf, Cursor, NumFails, CurIP, LastSyncedXid >>

admin == unblock

Next == admin
           \/ (\E self \in Devices: LocalDev(self))
           \/ (\E self \in ZabbixRecvs: zabbix_r(self))
           \/ (\E self \in ZabbixSyncs: zabbix_sync(self))

Spec == /\ Init /\ [][Next]_vars
        /\ \A self \in Devices : WF_vars(LocalDev(self))
        /\ \A self \in ZabbixRecvs : WF_vars(zabbix_r(self))
        /\ \A self \in ZabbixSyncs : WF_vars(zabbix_sync(self))

\* END TRANSLATION 

TypeOK ==   /\ DeviceState \in [Devices -> DeviceStateType]
            /\ SyncBuf \in [Devices -> SUBSET ServerDataType]
            /\ Cursor \in [ZabbixSyncs -> Nat]
            /\ SenderBuf \in [ZabbixRecvs -> SUBSET MsgType]
            /\ LocalLog \in [Devices -> SUBSET LocalEntryType]
            /\ LocalBlocklist \in [Devices -> SUBSET IPs]
            /\ GlobalBlocklist \in SUBSET ServerDataType
            /\ NumUnblocks \in 0..MaxUnblocks
            /\ NumFails \in [Devices -> 0..MaxFails]
            /\ CurIP \in [Devices -> IPs \cup {NULL}]
            /\ LastSyncedXid \in [Devices -> Nat]
                    
\* invariants

NormalDevs == {d \in Devices: DeviceState[d] = "NORMAL"}
GlobalBlocklistIPs == {entry.ip: entry \in {e \in GlobalBlocklist: e.unblocked = FALSE}}

DeviceSynchronized(d) == /\ \A entry \in LocalLog[d]: entry.sync = TRUE
                         /\ Cursor[SyncOf(d)] = NewestXid(GlobalBlocklist)

ConsistencyPerDevice == \A d \in Devices:
                DeviceSynchronized(d) => LocalBlocklist[d] = GlobalBlocklistIPs

SystemSynchronized ==  \A d \in Devices: DeviceSynchronized(d)

Consistency ==  SystemSynchronized
                =>
                \A d \in NormalDevs: LocalBlocklist[d] = GlobalBlocklistIPs

CheckingInvariant == ConsistencyPerDevice 

Witness == /\ \E d \in Devices: DeviceSynchronized(d) /\ LocalBlocklist[d] /= {}
Reachability == ~Witness

ValidIPStates == \A d \in NormalDevs: \A ip \in LocalBlocklist[d]:
                        \/ \E entry \in LocalLog[d]: entry.ip = ip /\ entry.sync = FALSE /\ entry.unblocked = FALSE \* blocked locally
                        \/ ip \in GlobalBlocklistIPs \* reported to the cloud
                        \/ \E e \in GlobalBlocklist: e.ip = ip /\ e.unblocked = TRUE /\ Cursor[SyncOf(d)] < e.xid \* unblocked not synced to device yet

LocalLogUnique == \A d \in Devices: \A e1, e2 \in LocalLog[d]: (e1.ip = e2.ip) => (e1 = e2)
GlobalBlocklistUnique == \A e1, e2 \in GlobalBlocklist: (e1.ip = e2.ip) => (e1 = e2)

EventualConsistency == <>[](\A d \in Devices : LocalBlocklist[d] = GlobalBlocklistIPs)

=============================================================================
\* Modification History
\* Last modified Wed May 20 15:46:20 JST 2026 by yin
\* Last modified Thu Apr 23 17:13:52 JST 2026 by jie
\* Created Fri Feb 13 17:15:16 JST 2026 by jie
