(* Copyright 2020 IOTA Stiftung *)
(* SPDX-License-Identifier: Apache-2.0 *)

Require Import PeanoNat.

Definition pad x N :=
  match x mod N with 0 => 0 | r => N - r end.

Definition aligned x N := pad x N = 0.

Lemma aligned_zero {N}: aligned 0 N.
Proof.
  unfold aligned, pad.
  induction N.
  - auto.
  - simpl.
    rewrite Nat.sub_diag.
    reflexivity.
Qed.

Lemma aligned_mod {x N}: aligned x N <-> x mod N = 0.
Proof.
  split.
  + intro H.
    unfold aligned, pad in H.
    destruct N.
    - reflexivity.
    - assert (P: 0 < S N - x mod S N).
      {
        unfold lt.
        rewrite <- (Nat.sub_diag (x mod S N)), <- Nat.sub_succ_l by auto.
        refine (Nat.sub_le_mono_r _ _ _ _).
        refine (proj2 (Nat.mod_bound_pos _ _ (le_0_n _) (le_n_S 0 _ (le_0_n _)))).
      }
      destruct (x mod S N).
      ++ reflexivity.
      ++ rewrite H in P.
         discriminate (proj1 (Nat.le_0_r 1) P).
  + intro H.
    unfold aligned, pad.
    rewrite H.
    reflexivity.
Qed.

Lemma round_left_cancel {N a} b: aligned a N -> pad (a + b) N = pad b N.
Proof.
  intro H.
  unfold pad.
  case (Nat.eq_dec N 0).
  - intro z. rewrite z. auto.
  - intro nz.
    rewrite <- (Nat.add_mod_idemp_l a b _ nz), (proj1 aligned_mod H), Nat.add_0_l.
    reflexivity.
Qed.

Axiom accessible : nat -> Prop.
Definition accessible_range b n :=
  forall m, m < n -> accessible (b + m).
Definition mmap P n :=
  exists p, aligned p P /\ accessible_range p n.
