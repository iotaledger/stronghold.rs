(* Copyright 2020 IOTA Stiftung *)
(* SPDX-License-Identifier: Apache-2.0 *)

Require Import PeanoNat.

Definition pad x N :=
  match x mod N with 0 => 0 | r => N - r end.

Definition aligned x N := (N <> 0) /\ pad x N = 0.

Lemma aligned_zero N: aligned 0 (S N).
Proof.
  split.
  all: unfold pad; try rewrite Nat.mod_0_l; auto.
Qed.

Lemma unaligned x: aligned x 1.
Proof.
  now split.
Qed.

Lemma aligned_mod {x N}: aligned x N -> x mod N = 0.
Proof.
  intros.
  destruct H as [Nz P].
  unfold pad in P.

  assert (Q: 0 < N - x mod N). {
    unfold lt.
    rewrite <- (Nat.sub_diag (x mod N)), <- Nat.sub_succ_l by auto.
    refine (Nat.sub_le_mono_r _ _ _ _).
    refine (proj2 (Nat.mod_bound_pos _ _ (le_0_n _) _)).
    now apply Nat.neq_0_lt_0.
  }

  destruct (x mod N). auto.
  rewrite P in Q.
  discriminate (proj1 (Nat.le_0_r 1) Q).
Qed.

Lemma aligned_mod_succ {x N}: aligned x (S N) <-> x mod (S N) = 0.
Proof.
  split.
  + apply aligned_mod.
  + intro H. unfold aligned.
    split.
    - auto.
    - unfold pad; now rewrite H.
Qed.

Lemma aligned_add_pad x {A}: A <> 0 -> aligned (x + pad x A) A.
Proof.
  intro Anz.
  case_eq A.
  + intro A0. exfalso. now refine (Anz _).
  + intros n _.
    refine (proj2 aligned_mod_succ _).
    unfold pad.
    case (Nat.eq_dec (x mod S n) 0).
    - intro H. now rewrite H, Nat.add_0_r.
    - intro H.
      rewrite <- (Nat.succ_pred _ H).
      rewrite -> (Nat.succ_pred _ H).
      rewrite <- (Nat.add_mod_idemp_l _ _ _ (Nat.neq_succ_0 _)).
      rewrite (Nat.add_sub_assoc _ _ _ (Nat.lt_le_incl _ _ (Nat.mod_upper_bound _ _ (Nat.neq_succ_0 _)))).
      rewrite Nat.add_comm.
      rewrite <- (Nat.add_sub_assoc _ _ _ (le_n _)).
      rewrite Nat.sub_diag, Nat.add_0_r.
      apply (Nat.mod_same _ (Nat.neq_succ_0 _)).
Qed.

Lemma round_left_cancel {N a} b: aligned a (S N) -> pad (a + b) (S N) = pad b (S N).
Proof.
  intro A.
  unfold pad.
  rewrite <- (Nat.add_mod_idemp_l a b _ (proj1 A)).
  now rewrite (aligned_mod A), Nat.add_0_l.
Qed.

Axiom accessible : nat -> Prop.
Definition accessible_range b n := forall m, m < n -> accessible (b + m).
Definition mmap P := forall n, {p | aligned p P /\ accessible_range p n}.

Record Allocation (n A P: nat) := mkAllocation {
  data: nat;
  data_alignment: aligned data A;
  data_accessible: accessible_range data n;

  pad_pre: nat;
  page_alignment_pre: aligned (data - pad_pre) P;
  pad_post: nat;
  page_alignment_post: aligned (data + n + pad_post) P;
}.

Lemma naive_allocator {P} (M: mmap P):
  forall n {A}, aligned P A -> Allocation n A P.
Proof.
  intros n A.

  pose (N := P + n).
  destruct (M N) as [x [XP XAcc]].
  pose (Pnz := proj1 XP).
  pose (k := (pad (x + P) A) / P).
  pose (p0 := (pad (x + P) A) mod P).
  pose (pi i := p0 + i * A).
  pose (di i := x + (1 + k) * P + pi i).
  pose (qi i := pad (di i + n) P).

  intros PA.
  pose (Anz := proj1 PA).

  assert (XA: x mod A = 0). {
    destruct (proj1 (Nat.mod_divides x P Pnz) (aligned_mod XP)) as [i I].
    destruct (proj1 (Nat.mod_divides P A Anz) (aligned_mod PA)) as [j J].
    rewrite I, J.
    rewrite <- Nat.mul_assoc, Nat.mul_comm.
    apply (Nat.mod_mul _ _ Anz).
  }

  assert (XPA: (x + P) mod A = 0). {
    rewrite <- (Nat.add_mod_idemp_l x P A Anz).
    rewrite XA.
    exact (aligned_mod PA).
  }

  assert (P0: p0 = 0). {
    unfold p0 in *.
    unfold pad.
    rewrite XPA.
    apply (Nat.mod_0_l _ Pnz).
  }

  assert (K0: k = 0). {
    unfold k, pad.
    rewrite XPA.
    exact (Nat.div_0_l _ Pnz).
  }

  refine (mkAllocation n A P (di 0) _ _ (pi 0) _ (qi 0) _).
  all: unfold qi, di, pi.
  all: rewrite P0, Nat.add_0_l, Nat.mul_0_l, Nat.add_0_r.
  all: rewrite K0, Nat.add_0_r, Nat.mul_1_l.
  + split.
    - exact Anz.
    - unfold pad. now rewrite XPA.
  + intros i I.
    rewrite <- Nat.add_assoc.
    refine (XAcc _ _).
    exact (proj1 (Nat.add_lt_mono_l _ _ _) I).
  + rewrite Nat.sub_0_r.
    unfold aligned, pad.
    rewrite <- (Nat.add_mod_idemp_l _ _ _ Pnz).
    rewrite (aligned_mod XP), Nat.add_0_l.
    now rewrite Nat.mod_same.
  + now apply aligned_add_pad.
Qed.
