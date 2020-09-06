#include <cassert>
#include <cstdint>
#include <iostream>
#include <list>
#include <queue>
#include <unordered_map>
#include <utility>
#include <vector>

#define LIBC_CSU_INIT 0xb01130
#define RW_START 0x117f000
#define RW_END 0x1180000
#define ROOM_B2 (RW_START + 0x62)
#define ROOMS 0x10fed60

struct State {
  std::uint64_t AflAreaPtr;
  std::uint32_t AflPrevLoc;

  bool operator==(const State &Other) const {
    return std::tie(AflAreaPtr, AflPrevLoc) ==
           std::tie(Other.AflAreaPtr, Other.AflPrevLoc);
  }

  void Read(std::FILE *File) {
    int r = std::fread(&AflAreaPtr, sizeof(AflAreaPtr), 1, File);
    assert(r == 1);
    r = std::fread(&AflPrevLoc, sizeof(AflPrevLoc), 1, File);
    assert(r == 1);
  }
};

namespace std {
template <> struct hash<State> {
  std::size_t operator()(const State &S) const noexcept {
    std::size_t H1 = std::hash<std::uint64_t>{}(S.AflAreaPtr);
    std::size_t H2 = std::hash<std::uint32_t>{}(S.AflPrevLoc);
    return H1 ^ (H2 << 1);
  }
};
} // namespace std

struct Edge {
  std::uint16_t Room;
  std::uint64_t Addr;
  struct Node *Prev;
  struct Node *Next;

  void Read(FILE *File, std::vector<std::pair<Node **, State>> &Patch);
};

struct Node {
  struct State State;
  std::vector<Edge> Succs;

  void Read(FILE *File, std::vector<std::pair<Node **, struct State>> &Patch) {
    State.Read(File);
    std::uint16_t SuccCount;
    int r = std::fread(&SuccCount, sizeof(SuccCount), 1, File);
    assert(r == 1);
    Succs.resize(SuccCount);
    for (int i = 0; i < SuccCount; i++) {
      Succs[i].Prev = this;
      Succs[i].Read(File, Patch);
    }
  };
};

void Edge::Read(FILE *File, std::vector<std::pair<Node **, State>> &Patch) {
  int r = std::fread(&Room, sizeof(Room), 1, File);
  assert(r == 1);
  r = std::fread(&Addr, sizeof(Addr), 1, File);
  assert(r == 1);
  Patch.emplace_back();
  Patch.back().first = &Next;
  Patch.back().second.Read(File);
}

void ReadGraph(std::unordered_map<State, Node *> &Nodes,
               std::vector<Node> &NodeStorage,
               std::vector<const Edge *> &Edges) {
  FILE *File = std::fopen("graph.bin", "r");
  assert(File != nullptr);
  std::uint32_t NodeCount;
  int r = std::fread(&NodeCount, sizeof(NodeCount), 1, File);
  assert(r == 1);
  NodeStorage.resize(NodeCount);
  std::vector<std::pair<Node **, State>> Patch;
  for (std::uint32_t i = 0; i < NodeCount; i++) {
    Node *Node = &NodeStorage[i];
    Node->Read(File, Patch);
    Nodes.insert(std::make_pair(Node->State, Node));
    for (const auto &Edge : Node->Succs)
      Edges.push_back(&Edge);
  }
  assert(Edges.size() == Patch.size());
  char Tmp;
  assert(std::fread(&Tmp, 1, 1, File) == 0);
  std::fclose(File);
  for (const auto &Pair : Patch) {
    auto It = Nodes.find(Pair.second);
    assert(It != Nodes.end());
    assert(It->second != nullptr);
    *Pair.first = It->second;
  }
}

bool ShortestPath(std::vector<Node *> &SP, std::vector<Node> &NodeStorage,
                  Node *Source, Node *Target) {
  std::vector<Node *> Prev(NodeStorage.size(), nullptr);
  std::deque<Node *> WorkList = {Source};
  while (!WorkList.empty()) {
    Node *WorkItem = WorkList.front();
    WorkList.pop_front();
    if (WorkItem == Target) {
      while (WorkItem != Source) {
        SP.push_back(WorkItem);
        WorkItem = Prev[WorkItem - NodeStorage.data()];
      }
      SP.push_back(Source);
      return true;
    }
    for (const Edge &Succ : WorkItem->Succs) {
      Node *NextNode = Succ.Next;
      if (!Prev[NextNode - NodeStorage.data()]) {
        Prev[NextNode - NodeStorage.data()] = WorkItem;
        WorkList.push_back(NextNode);
      }
    }
  }
  return false;
}

void ShortestPath() {
  std::unordered_map<State, Node *> Graph;
  std::vector<Node> NodeStorage;
  NodeStorage.resize(3);
  NodeStorage[0].State = {0, 0};
  Graph[NodeStorage[0].State] = &NodeStorage[0];
  NodeStorage[1].State = {1, 1};
  Graph[NodeStorage[1].State] = &NodeStorage[1];
  NodeStorage[2].State = {2, 2};
  Graph[NodeStorage[2].State] = &NodeStorage[2];
  NodeStorage[0].Succs.emplace_back(
      Edge{0, 0, &NodeStorage[0], &NodeStorage[1]});
  NodeStorage[1].Succs.emplace_back(
      Edge{0, 0, &NodeStorage[1], &NodeStorage[2]});
  std::vector<Node *> SP;
  assert(ShortestPath(SP, NodeStorage, &NodeStorage[0], &NodeStorage[2]));
  std::vector<Node *> ExpSP = {&NodeStorage[2], &NodeStorage[1],
                               &NodeStorage[0]};
  assert(SP == ExpSP);
}

void PrintSeq(const std::vector<Node *> &Seq) {
  std::cout << "    [";
  for (size_t i = Seq.size() - 1; i > 0; i--) {
    Node *Prev = Seq[i];
    Node *Next = Seq[i - 1];
    for (size_t j = 0; j < Prev->Succs.size(); j++) {
      Edge *Succ = &Prev->Succs[j];
      if (Succ->Next == Next)
        std::cout << std::dec << Succ->Room << ", ";
    }
  }
  std::cout << "],  # ";
  for (size_t i = Seq.size() - 1; i > 0; i--) {
    Node *Prev = Seq[i];
    Node *Next = Seq[i - 1];
    for (size_t j = 0; j < Prev->Succs.size(); j++) {
      Edge *Succ = &Prev->Succs[j];
      if (Succ->Next == Next)
        std::cout << std::hex << Succ->Addr << ", ";
    }
  }
  std::cout << std::endl;
}

int main() {
  ShortestPath();
  std::unordered_map<State, Node *> Nodes;
  std::vector<Node> NodeStorage;
  std::vector<const Edge *> Edges;
  ReadGraph(Nodes, NodeStorage, Edges);
  Node *InitialNode = Nodes[State{0xb01130, 0}];
  std::unordered_map<std::uint64_t, std::vector<const Edge *>> Addrs2Edges;
  for (const Edge *Edge : Edges) {
    Addrs2Edges[Edge->Addr].push_back(Edge);
  }
  std::vector<Node *> SP;
  for (const Edge *RoomEdge : Addrs2Edges[ROOM_B2]) {
    std::uint32_t Room = RoomEdge->Room + 0x10000;
    std::uint64_t RoomPtrAddr = ROOMS + Room * 8;
    bool Ok = true;
    for (int i = 0; i < 6; i++) {
      if (Addrs2Edges.find(RoomPtrAddr + i) == Addrs2Edges.end()) {
        Ok = false;
        break;
      }
    }
    if (!Ok)
      continue;
    std::cout << "PTR = 0x" << std::hex << RoomPtrAddr << std::endl;
    if (RoomPtrAddr == 0x117f6a8) /* known infeasible */
      continue;

    /* inc seqs */
    std::unordered_map<int, std::vector<std::vector<Node *>>> Offs2Seqs;
    for (int i = 0; i < 6; i++) {
      std::cout << "I" << i << " " << std::flush;
      for (const Edge *IncEdge : Addrs2Edges[RoomPtrAddr + i]) {
        SP.clear();
        if (ShortestPath(SP, NodeStorage, IncEdge->Next, IncEdge->Prev)) {
          std::cout << "+" << std::flush;
          SP.push_back(IncEdge->Prev);
          Offs2Seqs[i].push_back(SP);
        } else {
          std::cout << "-" << std::flush;
        }
      }
      std::cout << std::endl;
    }
    if (Offs2Seqs.size() != 6)
      continue;

    /* next */
    for (const std::vector<Node *> &IncSeq0 : Offs2Seqs[0]) {
      std::vector<Node *> SP0;
      if (!ShortestPath(SP0, NodeStorage, InitialNode, IncSeq0[0]))
        continue;
      for (const std::vector<Node *> &IncSeq1 : Offs2Seqs[1]) {
        std::vector<Node *> SP1;
        if (!ShortestPath(SP1, NodeStorage, IncSeq0[0], IncSeq1[0]))
          continue;
        for (const std::vector<Node *> &IncSeq2 : Offs2Seqs[2]) {
          std::vector<Node *> SP2;
          if (!ShortestPath(SP2, NodeStorage, IncSeq1[0], IncSeq2[0]))
            continue;
          for (const std::vector<Node *> &IncSeq3 : Offs2Seqs[3]) {
            std::vector<Node *> SP3;
            if (!ShortestPath(SP3, NodeStorage, IncSeq2[0], IncSeq3[0]))
              continue;
            for (const std::vector<Node *> &IncSeq4 : Offs2Seqs[4]) {
              std::vector<Node *> SP4;
              if (!ShortestPath(SP4, NodeStorage, IncSeq3[0], IncSeq4[0]))
                continue;
              for (const std::vector<Node *> &IncSeq5 : Offs2Seqs[5]) {
                std::vector<Node *> SP5;
                if (!ShortestPath(SP5, NodeStorage, IncSeq4[0], IncSeq5[0]))
                  continue;
                std::vector<Node *> SP6;
                if (!ShortestPath(SP6, NodeStorage, IncSeq5[0], RoomEdge->Prev))
                  continue;
                SP6.insert(SP6.begin(), RoomEdge->Next);
                std::cout << "PTR = 0x" << std::hex << RoomPtrAddr << std::endl;
                std::cout << "POS_SEQS = [" << std::endl;
                PrintSeq(SP0);
                PrintSeq(SP1);
                PrintSeq(SP2);
                PrintSeq(SP3);
                PrintSeq(SP4);
                PrintSeq(SP5);
                PrintSeq(SP6);
                std::cout << "]" << std::endl;
                std::cout << "INC_SEQS = [" << std::endl;
                PrintSeq(IncSeq0);
                PrintSeq(IncSeq1);
                PrintSeq(IncSeq2);
                PrintSeq(IncSeq3);
                PrintSeq(IncSeq4);
                PrintSeq(IncSeq5);
                std::cout << "]" << std::endl;
              }
            }
          }
        }
      }
    }
  }
}