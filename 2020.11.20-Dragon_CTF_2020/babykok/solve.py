#!/usr/bin/env/python3
from pwn import *

SOLUTIONS = {
    b'forall A B,  ((((A -> B) -> A) -> A) -> B) -> B.': '''
Proof.
  firstorder.
''',
    b'forall (C:Prop) (T:Set) (B: T -> Prop), (exists x : T, C -> B x) -> C -> exists x : T, B x.': '''
Proof.
  intros C T B L proof_of_C.
  destruct L as [witness proof_of_witness].
  pose (proof_of_B_witness := proof_of_witness proof_of_C).
  now exists witness.
''',
    b'forall A B, A \\/ B -> B \\/ A.': '''
Proof.
  intros A B.
  intros A_or_B.
  case A_or_B.
    intros pA.
    refine (or_intror _).
      exact pA.
    intros pB.
    refine (or_introl _).
      exact pB.
''',
    b'forall A B C D: Prop,(A->B)/\\(C->D)/\\A/\\C -> B/\\D.': '''
Proof.
  intros A B C D.
  intros X.
  case X.
    intros A_implies_B.
    intros X4.
    case X4.
      intros C_implies_D.
      intros A_or_C.
      case A_or_C.
        intros proof_of_A.
        intros proof_of_C.
        pose (proof_of_B := A_implies_B proof_of_A).
        pose (proof_of_D := C_implies_D proof_of_C).
        refine (conj _ _).
          exact proof_of_B.
          exact proof_of_D.
''',
    b'forall (m n: nat),  m + n = n + m.': '''
Proof.
  intros m n.
  elim m.
    elim n.
    exact (eq_refl (0 + 0)).
    intros n0.
    intros X.
    simpl.
    rewrite <- X.
    simpl.
    exact (eq_refl (S n0)).
    intros n0.
    intros X.
    simpl.
    rewrite X.
    elim n.
      simpl.
      exact (eq_refl (S n0)).
      intros n1.
      intros Y.
      simpl.
      rewrite Y.
      exact (eq_refl (S (n1 + S n0))).
''',
    b'forall b1 b2, negb (b1 && b2) = orb (negb b1) (negb b2).': '''
Proof.
  intros b1 b2.
  case b1.
    case b2.
      simpl.
      exact (eq_refl false).
      simpl.
      exact (eq_refl true).
    case b2.
      simpl.
      exact (eq_refl true).
      simpl.
      exact (eq_refl true).
''',
    b'forall m n, (n + m) * (n + m) =  n * n + 2 * n * m + m * m.': '''
Proof.
  intros m n.
  rewrite mult_plus_distr_r.
  rewrite mult_plus_distr_l.
  rewrite mult_plus_distr_l.
  rewrite plus_assoc.
  rewrite (mult_comm m n).
  simpl.
  rewrite mult_plus_distr_r.
  rewrite plus_assoc.
  rewrite plus_0_r.
  reflexivity.
''',
    b'forall (n:nat) (l:list), n < length l -> exists a: A, nth l n = Some a.': '''
Proof.
unfold lt.
intro n.
induction n.
simpl.
intro l.
destruct l.
simpl.
inversion 1.
simpl.
inversion 1.
exists a.
f_equal.
exists a.
f_equal.
simpl.
intros l ie.
destruct l.
easy.
simpl.
pose (ie2 := ie).
apply le_Sn_le in ie2.
apply le_Sn_le in ie2.
simpl in ie2.
destruct n.
destruct l.
simpl in ie.
apply le_S_n in ie.
easy.
simpl.
exists a0.
f_equal.
simpl in ie.
pose (ie3 := ie).
apply le_S_n in ie3.
pose (IHn2 := IHn l ie3).
exact IHn2.
''',
}

# with better formatting:
'''
Theorem nth_in:  forall (n:nat) (l:list), n < length l -> exists a: A, nth l n = Some a.
Proof.
  unfold lt.
  intro n.
  induction n.
  - simpl.
    intro l.
    destruct l.
    + simpl.
      inversion 1.
    + simpl.
      inversion 1.
      * exists a.
        f_equal.
      * exists a.
        f_equal.
  - simpl.
    intros l ie.
    destruct l.
    + easy.
    + simpl.
      pose (ie2 := ie).
      apply le_Sn_le in ie2.
      apply le_Sn_le in ie2.
      simpl in ie2.
      destruct n.
      * destruct l.
        {
          simpl in ie.
          apply le_S_n in ie.
          easy.
        }
        {
          simpl.
          exists a0.
          f_equal.
        }
      * simpl in ie.
        pose (ie3 := ie).
        apply le_S_n in ie3.
        pose (IHn2 := IHn l ie3).
        exact IHn2.
Qed.
'''

if __name__ == '__main__':
    with remote('babykok.hackable.software', 1337) as tube:
        while True:
            tube.recvregex(r'Theorem .*: ')
            text = tube.recvline().strip()
            tube.send(SOLUTIONS[text])

# DrgnS{xxxx_my_c0q_for_4_flag_17bcbc34b7c565a766e335}
