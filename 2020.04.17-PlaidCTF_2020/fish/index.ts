type ZeroOne = [0, 1];
type True = true;
type GetItem<T extends Any[], U extends BitArray> = {
    "0": ((...u: U) => void) extends ((x: infer X, ...y: infer Y) => void) ? (Y extends BitArray ? GetItem<DropEverySecond<T>, Y> : Nothing) : Nothing;
    "1": ((...u: U) => void) extends ((x: infer X, ...y: infer Y) => void) ? (Y extends BitArray ? GetItem<DropEverySecond<Tail<T>>, Y> : Nothing) : Nothing;
    "Done": T[0];
    "Nothing": Nothing;
}[HasNoWeirdos<U> extends False ? "Nothing" : U extends [] ? "Done" : U[0] extends 0 ? "0" : "1"];
type Any = any;
type OneOne = [1, 1];
type MakeTree<T extends BitArray, U extends BitArray, V extends Tree, W extends Tree> = {
    "Left": Less<V extends {
        "Height": infer HeightV;
    } ? HeightV : ZeroZero, W extends {
        "Height": infer HeightW;
    } ? HeightW : ZeroZero> extends True ? W : V;
    "Right": Less<V extends {
        "Height": infer HeightV;
    } ? HeightV : ZeroZero, W extends {
        "Height": infer HeightW;
    } ? HeightW : ZeroZero> extends True ? V : W;
    "Key": T;
    "Value": U;
    "Height": Inc<Min<V extends {
        "Height": infer HeightV;
    } ? HeightV : ZeroZero, W extends {
        "Height": infer HeightW;
    } ? HeightW : ZeroZero>>;
};
type Head<T extends Any[]> = ((...t: T) => void) extends ((x: infer X, ...y: infer Y) => void) ? X : Nothing;
type Tail<T extends Any[]> = ((...t: T) => void) extends ((x: infer X, ...y: infer Y) => void) ? Y : Nothing;
type Append<T, U extends Any[]> = Reverse<Join<T, Reverse<U>>>;
type LoadUserInput<T extends BitArray[]> = Concat<Join<[], Join<[], T>>, [[1], [1], [0, 1, 0, 1], [1], [1, 0, 1], [0, 0, 0, 1], [0, 1], [1, 0, 1], [0, 1, 0, 0, 1, 0, 1, 1, 1, 1], [1], [1, 0, 1], [1, 1, 1], [1, 1, 1], [1], [1, 0, 1], [1, 1, 1], [1, 0, 1], [], [0, 1], [1], [1, 0, 1], [1], [1, 0, 1], [0, 0, 0, 1], [0, 1], [1, 0, 1], [0, 0, 1], [1], [1, 0, 1], [1, 1, 1], [1, 1, 1], [1, 0, 1], [0, 0, 1, 0, 0, 1], [0, 1], [1], [1, 0, 1], [0, 1, 0, 1], [0, 0, 0, 1], [1], [], [0, 0, 0, 1], [1], [1], [], [1], [1, 0, 1], [1], [1, 1, 1], [1, 0, 1], [0, 1, 0, 0, 1, 0, 1, 1, 1, 1], [0, 1, 0, 1], [0, 0, 1, 0, 0, 1, 1, 1], [1, 0, 1], [1], [1, 0, 1], [1], [0, 1], [1, 0, 1], [0, 0, 0, 1], [1, 1, 0, 1], [], [1, 1, 1], [1], [1], [1, 0, 1], [1], [0, 1, 1, 1], [0, 0, 1, 0, 1, 0, 1, 1, 0, 1], [1], [1, 0, 0, 1], [1, 0, 1], [1], [1, 0, 1], [1], [0, 1], [1, 0, 1], [0, 0, 1], [0, 1, 1, 1], [0, 0, 1, 0, 1, 0, 1, 1, 0, 1], [0, 1, 1, 1], [0, 0, 0, 0, 0, 1, 1, 0, 1, 1], [0, 1], [0, 1], [1, 0, 1], [1], [1, 0, 1], [1], [0, 1, 1, 1], [0, 0, 1, 0, 1, 0, 0, 0, 1, 1], [1], [1, 0, 0, 1], [1, 0, 1], [1], [1, 0, 1], [1], [0, 1], [1, 0, 1], [0, 0, 1], [0, 1, 1, 1], [0, 0, 1, 0, 1, 0, 0, 0, 1, 1], [0, 1, 1, 1], [0, 0, 0, 0, 0, 1, 1, 0, 1, 1], [0, 1], [0, 1], [1, 0, 1], [0, 1], [1], [0, 0, 1], [1, 0, 0, 1], [0, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1], [1], [1], [0, 1, 1, 0, 1, 0, 1, 1, 1, 1], [1], [1, 0, 1], [0, 1], [1, 1, 1], [1], [1, 0, 1], [0, 1, 0, 1], [0, 0, 0, 1], [1], [], [0, 0, 1], [1], [1], [0, 0, 1], [0, 0, 1, 1], [1, 0, 1], [1, 0, 0, 1], [], [1], [1, 0, 1, 1], [1], [1, 1, 1], [1, 0, 1, 1], [0, 1, 0, 0, 1, 0, 1, 1, 1, 1], [0, 1, 0, 1], [0, 0, 0, 0, 1, 0, 1], [1, 0, 1, 1], [0, 0, 1, 1], [1, 0, 0, 1], [1, 0, 1, 1], [], [1, 1, 1], [1, 0, 1], [1, 0, 0, 1], [0, 1, 0, 1], [0, 0, 0, 0, 0, 1], [1, 0, 1], [1], [1, 0, 1], [1, 0, 0, 1], [0, 1], [1], [0, 0, 1], [1, 0, 0, 1], [0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], [], [0, 0, 1, 1], [], [], [0, 1], [1, 0, 1], [0, 0, 0, 1], [1], [1, 0, 1], [1, 1, 1], [1, 1], [1, 0, 1], [0, 0, 0, 1], [0, 1], [1, 0, 1], [0, 0, 0, 1, 1, 0, 1, 1, 1, 1], [1], [1, 0, 1], [1, 1, 1], [1, 1, 1, 1], [0, 1], [1, 0, 1], [0, 0, 0, 1], [1], [1, 0, 1], [1, 1, 1], [1, 1], [1, 0, 1], [0, 0, 0, 1], [0, 1], [1, 0, 1], [0, 0, 1], [0, 1], [1, 0, 1], [0, 0, 0, 1, 1, 0, 1, 1, 1, 1], [1], [1, 0, 1], [1, 1, 1], [1, 1, 1, 1], [0, 0, 0, 1], [1, 0, 1], [1, 0, 1], [0, 1], [1, 0, 1], [1, 0, 0, 1], [1, 0, 1, 1], [1, 0, 1], [1, 0, 1], [1], [1, 0, 0, 1], [1, 0, 1], [0, 0, 1], [1, 0, 0, 1], [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], [1, 1, 1], [1, 0, 0, 1], [], [0, 1, 0, 1], [0, 0, 0, 1, 1], [1, 0, 0, 1], [0, 0, 0, 1], [1, 0, 1], [1, 0, 1], [1, 0, 1, 1], [1, 0, 1], [1, 0, 1], [1, 1, 1, 1], [0, 0, 0, 0, 1], [0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1], [1, 0, 0, 1], [0, 1, 0, 1, 1, 0, 1, 1], [0, 0, 0, 0, 1, 1, 1, 1], [0, 1, 0, 1, 1, 0, 1, 1], [1, 0, 0, 0, 0, 0, 1, 1], [0, 1, 1, 1, 0, 1, 1, 1], [1, 0, 0, 1, 0, 1, 0, 1], [0, 1, 0, 1, 0, 0, 1, 1], [0, 1, 0, 1, 1, 1, 0, 1], [0, 0, 0, 0, 1, 0, 1, 1], [1, 1, 0, 0, 0, 0, 1, 1], [1, 0, 0, 1, 0, 0, 0, 1], [1, 0, 1, 1, 0, 0, 0, 1], [0, 0, 0, 0, 0, 0, 0, 1], [0, 0, 0, 0, 0, 0, 0, 1], [0, 1, 0, 1, 1, 0, 1], [1, 0, 0, 0, 0, 1, 0, 1], [1, 1, 1, 0, 0, 0, 1, 1], [1, 0, 1, 0, 0, 0, 1], [1, 0, 0, 1, 1, 1, 1, 1], [0, 1, 0, 0, 1, 0, 1, 1], [0, 1, 0, 0, 0, 1, 0, 1], [0, 1, 0, 0, 1, 1, 1, 1], [1, 1, 0, 0, 0, 0, 1], [1, 1], [1, 1, 1, 1, 0, 0, 1], [0, 0, 0, 1, 0, 0, 1, 1], [0, 1, 0, 1, 1, 0, 1], [0, 0, 0, 1, 1, 0, 0, 1], [0, 1, 0, 0, 1, 0, 1], [1, 1, 1, 0, 1, 1, 0, 1], [1, 0, 1, 1, 1, 1, 1, 1]]>;
type False = false;
type RunVM<T extends UserInput> = RunVMImpl<InitVM<LoadUserInput<T>>> extends 0 ? Any : Nothing;
type Concat<T extends Any[], U extends Any[]> = ReverseConcat<Reverse<T>, U>;
type Min<T extends BitArray, U extends BitArray> = Less<T, U> extends True ? T : U;
type TypeEq<T, U> = T extends U ? (U extends T ? True : False) : False;
type StripTrailing0s<T extends BitArray> = StripLeading0sAndReverse<Reverse<T>>;
type Bit = 0 | 1;
type BitArray = Bit[];
type DropEverySecond<T extends Any[], U extends Any[] = []> = {
    "U": U;
    "Proceed": ((...t: T) => void) extends ((x: infer X, y: infer Y, ...z: infer Z) => void) ? DropEverySecond<Z, Append<X, U>> : ((...t: T) => void) extends ((x: infer X, ...y: infer Y) => void) ? Append<X, U> : Nothing;
    "Nothing": Nothing;
}[HasNoWeirdos<T> extends False ? "Nothing" : [] extends T ? "U" : "Proceed"];
type InitVM<T extends BitArray[]> = {
    "Mem": T;
    "PC": [1, 1, 0, 0, 1];
    "Regs": [[], [], [], []];
    "Trees": [undefined, undefined];
    "Stack": [];
};
type ZeroZero = [0, 0];
type OneZero = [1, 0];
type Nothing = True & False;
function Main<T>(magikarp: T & (DeepStripReadonly<T> extends infer U ? (U extends UserInput ? RunVM<U> : Nothing) : Nothing)) {
    let goldeen = (magikarp as any).map((x) => parseInt(x.join(""), 2).toString(16)).join("");
    let stunfisk = "";
    for (let i = 0;
        i < 1000000;
        i++) {
        stunfisk = require("crypto").createHash("sha512").update(stunfisk).update(goldeen).digest("hex");
    } let feebas = Buffer.from(stunfisk, "hex");
    let reLessid = Buffer.from("0ac503f1627b0c4f03be24bc38db102e39f13d40d33e8f87f1ff1a48f63a02541dc71d37edb35e8afe58f31d72510eafe042c06b33d2e037e8f93cd31cba07d7", "hex");
    for (var i = 0;
        i < 64;
        i++) {
        feebas[i] ^= reLessid[i];
    } console.log(feebas.toString("utf-8"));
}
type AddTable = [[[ZeroZero, OneZero], [OneZero, ZeroOne]], [[OneZero, ZeroOne], [ZeroOne, OneOne]]];
type Add<T extends BitArray, U extends BitArray, V extends Bit = 0, W extends BitArray = []> = {
    "Nothing": Nothing;
    "Process": AddTable[Head<T>][Head<U>][V] extends [infer X, infer Y] ? (Y extends Bit ? Add<Tail<T>, Tail<U>, Y, Append<X, W>> : Nothing) : Nothing;
    "EmptyT": Add<[0], U, V, W>;
    "EmptyU": Add<T, [0], V, W>;
    "Done": V extends 0 ? W : Append<V, W>;
}[HasNoWeirdos<T> extends False ? "Nothing" : HasNoWeirdos<U> extends False ? "Nothing" : T extends [] ? (U extends [] ? "Done" : "EmptyT") : U extends [] ? "EmptyU" : "Process"];
Main([
[0],
[1,0,0,1],
[1,1,1,1],
[0,1],
[1],
[0,0,1],
[1,1],
[0,0,0,1],
[0,1,0,1],
[1,0,1],
[1,0,1,1],
[1,1,0,1],
[0,1,1,1],
[0,1,1],
[1,1,1],
[0,0,1,1],
]);
type Neg<T extends BitArray> = And<T, AllOnes16> extends infer U ? Not<AssertIsBitArray<U>> extends infer V ? Add<AssertIsBitArray<V>, [1]> : Nothing : Nothing;
type BitwiseBinaryOperation<T extends BitArray, U extends BitArray, V extends [[Bit, Bit], [Bit, Bit]], W extends BitArray = []> = {
    "Nothing": Nothing;
    "Process": BitwiseBinaryOperation<Tail<T>, Tail<U>, V, Append<V[Head<T>][Head<U>], W>>;
    "EmptyT": BitwiseBinaryOperation<[0], U, V, W>;
    "EmptyU": BitwiseBinaryOperation<T, [0], V, W>;
    "W": W;
}[HasNoWeirdos<T> extends False ? "Nothing" : HasNoWeirdos<U> extends False ? "Nothing" : T extends [] ? (U extends [] ? "W" : "EmptyT") : U extends [] ? "EmptyU" : "Process"];
type Id<T> = { [Key in keyof T]: T[Key]; };
type RunVMImpl<T extends VMState> = (SingleStep<T> extends infer U ? {
    "Nothing": Nothing;
    "AsNumber": U extends BitArray ? AsNumber<U> : Nothing;
    "VMState": U extends VMState ? RunVMImpl<U> : Nothing;
}[U extends Nothing ? "Nothing" : U extends BitArray ? "AsNumber" : "VMState"] : Nothing);
type HasNoWeirdos<T extends Any[]> = {
    "True": True;
    "HandleTail": HasNoWeirdos<Tail<T>>;
    "False": False;
}[T extends [] ? "True" : T extends (infer U)[] ? (U[] extends T ? "False" : "HandleTail") : "HandleTail"];
type And<T extends BitArray, U extends BitArray> = BitwiseBinaryOperation<T, U, [[0, 0], [0, 1]]>;
type Eq<T extends BitArray, U extends BitArray> = {
    "False": False;
    "Process": T[0] extends U[0] ? (U[0] extends T[0] ? Eq<Tail<T>, Tail<U>> : False) : False;
    "EmptyT": Eq<[0], U>;
    "EmptyU": Eq<T, [0]>;
    "True": True;
}[HasNoWeirdos<T> extends False ? "False" : HasNoWeirdos<U> extends False ? "False" : T extends [] ? (U extends [] ? "True" : "EmptyT") : U extends [] ? "EmptyU" : "Process"];
type UserInput = [
    BitArray4, BitArray4, BitArray4, BitArray4,
    BitArray4, BitArray4, BitArray4, BitArray4,
    BitArray4, BitArray4, BitArray4, BitArray4,
    BitArray4, BitArray4, BitArray4, BitArray4,
    BitArray4];
type Join<T, U extends Any[]> = Parameters<(t: T, ...u: Id<U>) => void>;
type UnpackTree<T extends Tree> = T extends {
    "Key": infer Glass_catfish;
    "Value": infer Oregon_chub;
    "Left": infer Oscar;
    "Right": infer Quillback;
} ? [Glass_catfish, Oregon_chub, TreeMax<AssertIsTree<Oscar>, AssertIsTree<Quillback>>] : Nothing;
type Inc<T extends BitArray> = Add<T, [1]>;
type Madtom<T extends Tree, U extends BitArray, V extends BitArray> = TreeMax<T, MakeTree<U, V, undefined, undefined>>;
type MakeTreeFromHead<T extends [BitArray, BitArray, Tree][], U extends Tree> = {
    "Nothing": Nothing;
    "U": U;
    "Proceed": MakeTreeFromHead<Tail<T>, MakeTree<Head<T>[0], Head<T>[1], Head<T>[2], U>>;
}[HasNoWeirdos<T> extends False ? "Nothing" : T extends [] ? "U" : "Proceed"];
type SetTree<T extends VMState, U extends BitArray, V extends Tree | undefined> = {
    "Mem": T["Mem"];
    "PC": T["PC"];
    "Regs": T["Regs"];
    "Trees": SetItem<T["Trees"], U, V>;
    "Stack": T["Stack"];
};
type AssertIsTree<T> = T extends Tree ? T : Nothing;
type TreeMax<T extends Tree, U extends Tree, V extends [BitArray, BitArray, Tree][] = []> = {
    "U": MakeTreeFromHead<V, U>;
    "T": MakeTreeFromHead<V, T>;
    "ULess": U extends {
        "Right": infer RightU;
        "Left": infer LeftU;
        "Key": infer KeyU;
        "Value": infer ValueU;
    } ? TreeMax<AssertIsTree<RightU>, T, Join<[AssertIsBitArray<KeyU>, AssertIsBitArray<ValueU>, AssertIsTree<LeftU>], V>> : Nothing;
    "TLess": T extends {
        "Right": infer RightT;
        "Left": infer LeftT;
        "Key": infer KeyT;
        "Value": infer ValueT;
    } ? TreeMax<AssertIsTree<RightT>, U, Join<[AssertIsBitArray<KeyT>, AssertIsBitArray<ValueT>, AssertIsTree<LeftT>], V>> : Nothing;
}[T extends {
    "Key": infer KeyT;
} ? (KeyT extends BitArray ? (U extends {
    "Key": infer KeyU;
} ? (KeyU extends BitArray ? (Less<KeyU, KeyT> extends True ? "ULess" : "TLess") : "T") : "T") : "U") : "U"];
type Xor<T extends BitArray, U extends BitArray> = BitwiseBinaryOperation<T, U, [[0, 1], [1, 0]]>;
type AllZeroes<T extends BitArray, U extends Any[] = [0], V extends Any[] = []> = ({
    "Nothing": {
        "length": Nothing;
    };
    "0": ((...t: T) => void) extends ((x: infer X, ...y: infer Y) => void) ? AllZeroes<AssertIsBitArray<Y>, ReverseConcat<U, U>, V> : Nothing;
    "1": ((...t: T) => void) extends ((x: infer X, ...y: infer Y) => void) ? AllZeroes<AssertIsBitArray<Y>, ReverseConcat<U, U>, ReverseConcat<U, V>> : Nothing;
    "V": V;
}[HasNoWeirdos<T> extends False ? "Nothing" : T extends [] ? "V" : T[0] extends 0 ? "0" : "1"]);
type Tree = undefined | {
    "Left": Tree;
    "Right": Tree;
    "Key": BitArray;
    "Value": BitArray;
    "Height": BitArray;
};
type TwoTrees = [Tree | undefined, Tree | undefined];
type ReverseConcat<T extends Any[], U extends Any[]> = {
    "U": U;
    "Proceed": ((...t: T) => void) extends ((x: infer X, ...y: infer Y) => void) ? ReverseConcat<Y, Join<X, U>> : Nothing;
    "[]": [];
}[HasNoWeirdos<T> extends False ? "[]" : T extends [] ? "U" : "Proceed"];
type Store<T extends VMState, U extends BitArray, V extends BitArray> = [[Nothing, {
    "Mem": T["Mem"];
    "PC": T["PC"];
    "Regs": SetItem<T["Regs"], Tail<Tail<U>>, V>;
    "Trees": T["Trees"];
    "Stack": T["Stack"];
}], [{
    "Mem": SetItem<T["Mem"], Tail<Tail<U>>, V>;
    "PC": T["PC"];
    "Regs": T["Regs"];
    "Trees": T["Trees"];
    "Stack": T["Stack"];
}, {
    "Mem": SetItem<T["Mem"], GetItem<T["Regs"], Tail<Tail<U>>>, V>;
    "PC": T["PC"];
    "Regs": T["Regs"];
    "Trees": T["Trees"];
    "Stack": T["Stack"];
}]][OrElse0<GetItem<U, [1]>>][OrElse0<GetItem<U, []>>];
type Or<T extends BitArray, U extends BitArray> = BitwiseBinaryOperation<T, U, [[0, 1], [1, 1]]>;
type VMState = {
    "PC": BitArray;
    "Mem": BitArray[];
    "Regs": BitArray4x4;
    "Trees": TwoTrees;
    "Stack": BitArray[];
};
type BitArray4x4 = [BitArray, BitArray, BitArray, BitArray];
type SetItem<T extends Any[], U extends BitArray, V, W extends BitArray = [], X extends Any[] = []> = {
    "Nothing": Nothing;
    "Proceed": SetItem<Tail<T>, U, V, Inc<W>, Append<T[0], X>>;
    "Done": Concat<Append<V, X>, Tail<T>>;
    "X": X;
}[HasNoWeirdos<T> extends False ? "Nothing" : HasNoWeirdos<U> extends False ? "Nothing" : Eq<U, W> extends True ? "Done" : T extends [] ? "X" : "Proceed"];
type Load<T extends VMState, U extends BitArray> = [
    [Tail<Tail<U>>, GetItem<T["Regs"], Tail<Tail<U>>>],
    [GetItem<T["Mem"], Tail<Tail<U>>>, GetItem<T["Mem"], GetItem<T["Regs"], Tail<Tail<U>>>>]
][OrElse0<GetItem<U, [1]>>][OrElse0<GetItem<U, []>>];
type AllOnes16 = [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
type Reverse<T extends Any[]> = ReverseConcat<T, []>;
type Less<T extends BitArray, U extends BitArray, V extends boolean = False> = {
    "Nothing": Nothing;
    "Proceed": TypeEq<Head<T>, Head<U>> extends True ? Less<Tail<T>, Tail<U>, V> : Head<T> extends 1 ? Less<Tail<T>, Tail<U>, False> : Less<Tail<T>, Tail<U>, True>;
    "EmptyT": Less<[0], U, V>;
    "EmptyU": Less<T, [0], V>;
    "V": V;
}[HasNoWeirdos<T> extends False ? "Nothing" : HasNoWeirdos<U> extends False ? "Nothing" : T extends [] ? (U extends [] ? "V" : "EmptyT") : U extends [] ? "EmptyU" : "Proceed"];
type OrElse0<T> = T extends Nothing | undefined ? 0 : T;
type SingleStep<T extends VMState> =
    (Eq<GetItem<T["Mem"], T["PC"]>, []> extends False ?
        Nothing :
        Load<T, GetItem<T["Mem"], Inc<T["PC"]>>>) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [1]> extends False ?
        Nothing :
        (Load<T, GetItem<T["Mem"], Inc<Inc<T["PC"]>>>> extends infer Elasmobranch ?
            SetPC<Store<T, GetItem<T["Mem"], Inc<T["PC"]>>, AssertIsBitArray<Elasmobranch>>, Inc<Inc<Inc<T["PC"]>>>> :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [0, 1]> extends False ?
        Nothing :
        ([Load<T, GetItem<T["Mem"], Inc<T["PC"]>>>, Load<T, GetItem<T["Mem"], Inc<Inc<T["PC"]>>>>] extends [infer Inanga, infer Climbing_gourami] ?
            (Add<AssertIsBitArray<Inanga>, AssertIsBitArray<Climbing_gourami>> extends infer Rock_Eq2 ?
                SetPC<Store<T, GetItem<T["Mem"], Inc<T["PC"]>>, AssertIsBitArray<Rock_Eq2>>, Inc<Inc<Inc<T["PC"]>>>> :
                Nothing) :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [1, 1]> extends False ?
        Nothing :
        ([Load<T, GetItem<T["Mem"], Inc<T["PC"]>>>, Load<T, GetItem<T["Mem"], Inc<Inc<T["PC"]>>>>] extends [infer Dojo_loach, infer Blue_whiting] ?
            (Mul<AssertIsBitArray<Dojo_loach>, AssertIsBitArray<Blue_whiting>> extends infer Snake_eel ?
                SetPC<Store<T, GetItem<T["Mem"], Inc<T["PC"]>>, AssertIsBitArray<Snake_eel>>, Inc<Inc<Inc<T["PC"]>>>> :
                Nothing) :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [0, 0, 1]> extends False ?
        Nothing :
        ([Load<T, GetItem<T["Mem"], Inc<T["PC"]>>>, Load<T, GetItem<T["Mem"], Inc<Inc<T["PC"]>>>>] extends [infer Ladyfish, infer Tigerperch] ?
            (And<AssertIsBitArray<Ladyfish>, AssertIsBitArray<Tigerperch>> extends infer Silver_carp ?
                SetPC<Store<T, GetItem<T["Mem"], Inc<T["PC"]>>, StripTrailing0s<AssertIsBitArray<Silver_carp>>>, Inc<Inc<Inc<T["PC"]>>>> :
                Nothing) :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [1, 0, 1]> extends False ?
        Nothing :
        ([Load<T, GetItem<T["Mem"], Inc<T["PC"]>>>, Load<T, GetItem<T["Mem"], Inc<Inc<T["PC"]>>>>] extends [infer Gar, infer North_American_darter] ?
            (Or<AssertIsBitArray<Gar>, AssertIsBitArray<North_American_darter>> extends infer Blackfin_Tuna ?
                SetPC<Store<T, GetItem<T["Mem"], Inc<T["PC"]>>, AssertIsBitArray<Blackfin_Tuna>>, Inc<Inc<Inc<T["PC"]>>>> :
                Nothing) :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [0, 1, 1]> extends False ?
        Nothing :
        ([Load<T, GetItem<T["Mem"], Inc<T["PC"]>>>, Load<T, GetItem<T["Mem"], Inc<Inc<T["PC"]>>>>] extends [infer Sixgill_shark, infer Knifefish] ?
            (Xor<AssertIsBitArray<Sixgill_shark>, AssertIsBitArray<Knifefish>> extends infer Flier ?
                SetPC<Store<T, GetItem<T["Mem"], Inc<T["PC"]>>, StripTrailing0s<AssertIsBitArray<Flier>>>, Inc<Inc<Inc<T["PC"]>>>> :
                Nothing) :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [1, 1, 1]> extends False ?
        Nothing :
        ([Load<T, GetItem<T["Mem"], Inc<T["PC"]>>>, Load<T, GetItem<T["Mem"], Inc<Inc<T["PC"]>>>>] extends [infer Kafue_pike, infer Snakehead] ?
            (Eq<AssertIsBitArray<Kafue_pike>, AssertIsBitArray<Snakehead>> extends True ?
                SetPC<Store<T, GetItem<T["Mem"], Inc<T["PC"]>>, []>, Inc<Inc<Inc<T["PC"]>>>> :
                SetPC<Store<T, GetItem<T["Mem"], Inc<T["PC"]>>, [1]>, Inc<Inc<Inc<T["PC"]>>>>) :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [0, 0, 0, 1]> extends False ?
        Nothing :
        (Load<T, GetItem<T["Mem"], Inc<Inc<T["PC"]>>>> extends infer Barreleye ?
            (Neg<AssertIsBitArray<Barreleye>> extends infer Sandfish ?
                SetPC<Store<T, GetItem<T["Mem"], Inc<T["PC"]>>, StripTrailing0s<AssertIsBitArray<Sandfish>>>, Inc<Inc<Inc<T["PC"]>>>> :
                Nothing) :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [1, 0, 0, 1]> extends False ?
        Nothing :
        Load<T, GetItem<T["Mem"], Inc<T["PC"]>>> extends infer Spanish_mackerel ?
        (And<Add<AssertIsBitArray<Spanish_mackerel>, Inc<Inc<T["PC"]>>>, AllOnes16> extends infer Tetra ?
            SetPC<T, StripTrailing0s<AssertIsBitArray<Tetra>>> :
            Nothing) :
        Nothing) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [0, 1, 0, 1]> extends False ?
        Nothing :
        ([Load<T, GetItem<T["Mem"], Inc<T["PC"]>>>, Load<T, GetItem<T["Mem"], Inc<Inc<T["PC"]>>>>] extends [infer Noodlefish, infer Luminous_AllZeroes] ?
            (Eq<AssertIsBitArray<Luminous_AllZeroes>, []> extends True ?
                (And<Add<AssertIsBitArray<Noodlefish>, Inc<Inc<Inc<T["PC"]>>>>, AllOnes16> extends infer Prickly_shark ?
                    SetPC<T, StripTrailing0s<AssertIsBitArray<Prickly_shark>>> :
                    Nothing) :
                SetPC<T, Inc<Inc<Inc<T["PC"]>>>>) :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [1, 1, 0, 1]> extends False ?
        Nothing :
        ([Load<T, GetItem<T["Mem"], Inc<T["PC"]>>>, Load<T, GetItem<T["Mem"], Inc<Inc<T["PC"]>>>>, Load<T, GetItem<T["Mem"], Inc<Inc<Inc<T["PC"]>>>>>] extends [infer Threespine_stickleback, infer Cobia, infer Banded_EmptyU] ?
            (Madtom<GetTree<T, AssertIsBitArray<Threespine_stickleback>>, AssertIsBitArray<Cobia>, AssertIsBitArray<Banded_EmptyU>> extends infer Damselfish ?
                (Damselfish extends Tree ?
                    (SetTree<T, AssertIsBitArray<Threespine_stickleback>, Damselfish> extends infer Leopard_danio ?
                        (Leopard_danio extends VMState ?
                            SetPC<Leopard_danio, Inc<Inc<Inc<Inc<T["PC"]>>>>> :
                            Nothing) :
                        Nothing) :
                    Nothing) :
                Nothing) :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [0, 0, 1, 1]> extends False ?
        Nothing :
        ([Load<T, GetItem<T["Mem"], Inc<Inc<Inc<T["PC"]>>>>>] extends [infer Murray_Eq2] ?
            (UnpackTree<GetTree<T, AssertIsBitArray<Murray_Eq2>>> extends [infer Arapaima, infer Fire_goby, infer Round_whitefish] ?
                (SetTree<Store<Store<T, GetItem<T["Mem"], Inc<T["PC"]>>, AssertIsBitArray<Arapaima>>, GetItem<T["Mem"], Inc<Inc<T["PC"]>>>, AssertIsBitArray<Fire_goby>>, AssertIsBitArray<Murray_Eq2>, AssertIsTree<Round_whitefish>> extends infer Southern_Dolly_Varden ?
                    (Southern_Dolly_Varden extends VMState ?
                        SetPC<Southern_Dolly_Varden, Inc<Inc<Inc<Inc<T["PC"]>>>>> :
                        Nothing) :
                    Nothing) :
                Nothing) :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [1, 0, 1, 1]> extends False ?
        Nothing :
        (Load<T, GetItem<T["Mem"], Inc<Inc<T["PC"]>>>> extends infer Roanoke_bass ?
            (And<AllOnes16, AssertIsBitArray<Roanoke_bass>> extends infer Hammerjaw ?
                SetPC<Store<T, GetItem<T["Mem"], Inc<T["PC"]>>, StripTrailing0s<AssertIsBitArray<Hammerjaw>>>, Inc<Inc<Inc<T["PC"]>>>> :
                Nothing) :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [0, 1, 1, 1]> extends False ?
        Nothing :
        (Load<T, GetItem<T["Mem"], Inc<T["PC"]>>> extends infer Asian_carps ?
            (SetPC<SetStack<T, Join<Inc<Inc<T["PC"]>>, T["Stack"]>>, Asian_carps>) :
            Nothing)) |
    (Eq<GetItem<T["Mem"], T["PC"]>, [1, 1, 1, 1]> extends False ?
        Nothing :
        SetPC<SetStack<T, Tail<T["Stack"]>>, Head<T["Stack"]>>);
type AsNumber<T extends BitArray> = AllZeroes<StripTrailing0s<T>>["length"];
type Not<T extends BitArray, U extends BitArray = []> = {
    "Nothing": Nothing;
    "1": Not<Tail<T>, Append<1, U>>;
    "0": Not<Tail<T>, Append<0, U>>;
    "U": U;
}[HasNoWeirdos<T> extends False ? "Nothing" : T extends [] ? "U" : T[0] extends 0 ? "1" : "0"];
type StripLeading0sAndReverse<T extends BitArray> = {
    "HandleTail": StripLeading0sAndReverse<Tail<T>>;
    "Reverse": Reverse<T>;
    "[]": [];
}[T extends [] ? "[]" : Head<T> extends 0 ? "HandleTail" : "Reverse"];
type GetTree<T extends VMState, U extends BitArray> = GetItem<T["Trees"], U>;
type BitArray4 = BitArray & {
    "length": 4;
};
type SetStack<T extends VMState, U> = {
    "Mem": T["Mem"];
    "PC": T["PC"];
    "Regs": T["Regs"];
    "Trees": T["Trees"];
    "Stack": U;
};
type DeepStripReadonly<T> = { -readonly [Key in keyof T]: DeepStripReadonly<T[Key]>; };
type SetPC<T extends VMState, U> = {
    "Mem": T["Mem"];
    "PC": U;
    "Regs": T["Regs"];
    "Trees": T["Trees"];
    "Stack": T["Stack"];
};
type Mul<T extends BitArray, U extends BitArray, V extends BitArray = []> = {
    "Nothing": Nothing;
    "0": Mul<Tail<T>, Join<0, U>, V>;
    "1": Mul<Tail<T>, Join<0, U>, Add<U, V>>;
    "V": V;
}[HasNoWeirdos<T> extends False ? "Nothing" : T extends [] ? "V" : T[0] extends 0 ? "0" : "1"];
type AssertIsBitArray<T> = T extends BitArray ? T : Nothing;
