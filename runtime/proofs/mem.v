(* Copyright 2020 IOTA Stiftung *)
(* SPDX-License-Identifier: Apache-2.0 *)

Require Import PeanoNat.
Require Import Psatz.

(* x = mmap N                            *)
(* |   | p |     n    | q | guard |      *)
(* P   P   A              P              *)
(*                                       *)
(* Question: how can we minimize q?      *)

Definition pad x N :=
  match x mod N with 0 => 0 | r => N - r end.

Lemma pad_le {A x y}: A <> 0 ->
  0 < y mod A <= x mod A -> pad x A <= pad y A.
Proof.
  intros.
  unfold pad.
  case_eq (x mod A); case_eq (y mod A); intros; lia.
Qed.

Lemma pad_add_l a b c: c <> 0 -> a mod c = 0 -> pad (a + b) c = pad b c.
Proof.
  intros Cnz AC.
  unfold pad.
  now rewrite <- (Nat.add_mod_idemp_l _ _ _ Cnz), AC.
Qed.

Lemma pad_add_r a b c: c <> 0 -> b mod c = 0 -> pad (a + b) c = pad a c.
Proof.
  intros Cnz AC.
  rewrite Nat.add_comm.
  now apply pad_add_l.
Qed.

Lemma pad_0 {A}: A <> 0 -> pad 0 A = 0.
Proof.
  intro Anz.
  unfold pad.
  now rewrite (Nat.mod_0_l _ Anz).
Qed.

Definition pad_minimizer a b c :=
  if b mod c =? 0 then 0 else
  if b mod c mod a =? 0
  then c / a - b mod c / a
  else c / a - 1 - b mod c / a.

Lemma pad_minimizer_bound a b c:
  a <> 0 -> pad_minimizer a b c <= c / a.
Proof.
  intros Anz.
  unfold pad_minimizer.
  case (b mod c =? 0); case ((b mod c mod a) =? 0); lia.
Qed.

Lemma pad_add_small x y A: A <> 0 -> x < pad y A -> x + pad (x + y) A = pad y A.
Proof.
  intros Anz L.
  unfold pad in *.
  case_eq (y mod A).
  - intro z; rewrite z in L; lia.
  - intros n N.
    rewrite N, <- N in L.
    pose (K := proj1 (Nat.add_lt_mono_r x (A - y mod A) (y mod A)) L).
    rewrite (Nat.sub_add _ _ (Nat.lt_le_incl _ _ (Nat.mod_upper_bound y _ Anz))) in K.
    rewrite <- (Nat.add_mod_idemp_r _ _ _ Anz), (Nat.mod_small _ _ K).
    case_eq (x + y mod A); lia.
Qed.

Lemma pad_min a b c: c mod a = 0 ->
  let i := pad_minimizer a b c in
  forall j, pad (a * i + b) c <= pad (a * j + b) c.
Proof.
  intros CA m.
  case (Nat.eq_dec c 0); [intro z; now rewrite z|]; intro Cnz.
  case (Nat.eq_dec a 0); [intro z; now rewrite z|]; intro Anz.
  destruct (proj1 (Nat.mod_divides _ a Anz) CA) as [j J].

  case (Nat.eq_dec (b mod c) 0).
  - intros z i.
    rewrite (pad_add_r _ _ _ Cnz z).
    unfold m, pad_minimizer.
    rewrite (proj2 (Nat.eqb_eq _ _) z).
    rewrite Nat.mul_0_r.
    rewrite (pad_0 Cnz).
    apply Nat.le_0_l.
  - intros nz i.
    case (Nat.eq_dec (b mod c mod a) 0).
    + intros R.
      destruct (proj1 (Nat.mod_divides _ a Anz) R) as [k K].
      assert (m = j - k) as M. {
        unfold m, pad_minimizer.
        rewrite (proj2 (Nat.eqb_neq _ _) nz).
        rewrite (proj2 (Nat.eqb_eq _ _) R), K, J.
        now repeat rewrite Nat.mul_comm, (Nat.div_mul _ _ Anz).
      }
      rewrite M.

      unfold pad.
      rewrite <- (Nat.add_mod_idemp_r _ b c Cnz), K.
      rewrite <- Nat.mul_add_distr_l.

      assert (k <= j) as KJ. {
        refine (Nat.lt_le_incl _ _ _).
        pose (L := Nat.mod_upper_bound b c Cnz).
        rewrite K, J in L.
        exact (proj2 (Nat.mul_lt_mono_pos_l a k j (proj1 (Nat.neq_0_lt_0 _) Anz)) L).
      }
      rewrite (Nat.sub_add k j KJ).

      rewrite <- J, (Nat.mod_same _ Cnz).
      apply Nat.le_0_l.
    + intro R.
      destruct j; [exfalso; rewrite Nat.mul_0_r in J; now apply Cnz|].

      pose (k := b mod c / a).
      pose (r := b mod c mod a).
      assert (m = j - k) as M. {
        unfold m, pad_minimizer.
        rewrite (proj2 (Nat.eqb_neq _ _) nz).
        rewrite (proj2 (Nat.eqb_neq _ _) R).
        rewrite J.
        rewrite Nat.mul_comm at 1.
        now rewrite (Nat.div_mul _ _ Anz), Nat.sub_1_r, Nat.pred_succ, <- J.
      }
      rewrite M.

      refine (pad_le Cnz _).
      repeat rewrite <- (Nat.add_mod_idemp_r _ b c Cnz).
      rewrite (Nat.div_mod (b mod c) a Anz).
      fold k. fold r.
      repeat rewrite Nat.add_assoc, <- Nat.mul_add_distr_l.

      assert (k <= j) as KJ. {
        unfold k.
        refine (proj1 (Nat.lt_succ_r _ _) _).
        refine (Nat.div_lt_upper_bound _ _ _ Anz _).
        rewrite <- J.
        exact (Nat.mod_upper_bound _ _ Cnz).
      }
      rewrite (Nat.sub_add _ _ KJ).

      assert (a * j + r < c) as AJRC. {
        rewrite J.
        rewrite Nat.mul_succ_r.
        refine (proj1 (Nat.add_lt_mono_l _ _ _) _).
        apply (Nat.mod_upper_bound (b mod c) _ Anz).
      }
      rewrite (Nat.mod_small _ _ AJRC).

      rewrite <- (Nat.add_mod_idemp_l _ _ _ Cnz), J.
      rewrite (Nat.mul_mod_distr_l _ _ _ (Nat.neq_succ_0 _) Anz).

      assert (a * ((i + k) mod S j) + r < a * S j) as l. {
        rewrite Nat.mul_succ_r.
        refine (Nat.add_le_lt_mono _ _ _ _ _ _).
        - refine (proj1 (Nat.mul_le_mono_pos_l _ _ _ (proj1 (Nat.neq_0_lt_0 _) Anz)) _).
          refine (proj2 (Nat.succ_le_mono _ _) _).
          exact (Nat.mod_upper_bound _ _ (Nat.neq_succ_0 _)).
        - now apply Nat.mod_upper_bound.
      }
      rewrite (Nat.mod_small _ _ l).

      split.
      ++ rewrite <- (Nat.add_0_l 0).
         refine (Nat.add_le_lt_mono _ _ _ _ (Nat.le_0_l _) _).
         now refine (proj1 (Nat.neq_0_lt_0 _) _).
      ++ refine (proj1 (Nat.add_le_mono_r _ _ _) _).
         refine (proj1 (Nat.mul_le_mono_pos_l _ _ _ (proj1 (Nat.neq_0_lt_0 _) Anz)) _).
         refine (proj1 (Nat.lt_succ_r _ _) _).
         exact (Nat.mod_upper_bound _ _ (Nat.neq_succ_0 _)).
Qed.

Definition aligned x N := N <> 0 /\ pad x N = 0.

Lemma aligned_zero N: aligned 0 (S N).
Proof.
  split; unfold pad; try rewrite Nat.mod_0_l; auto.
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
    split; [|unfold pad; rewrite H]; auto.
Qed.

Lemma aligned_add_pad x {A}: A <> 0 -> aligned (x + pad x A) A.
Proof.
  intro Anz.
  case_eq A.
  + intro. exfalso. now apply Anz.
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

Lemma align_left_cancel {N a} b: aligned a N -> pad (a + b) N = pad b N.
Proof.
  intro A.
  refine (pad_add_l _ _ _ (proj1 A) _).
  exact (aligned_mod A).
Qed.

Lemma align_weaken {A B} x: aligned A B -> aligned x A -> aligned x B.
Proof.
  intros AB XA.
  destruct (proj1 (Nat.mod_divides _ _ (proj1 AB)) (aligned_mod AB)) as [p P].
  rewrite P in XA.
  destruct (proj1 (Nat.mod_divides _ _ (proj1 XA)) (aligned_mod XA)) as [q Q].
  rewrite Q.
  refine (conj (proj1 AB) _).
  unfold pad.
  rewrite <- Nat.mul_assoc, Nat.mul_comm.
  now rewrite (Nat.mod_mul (p * q) B (proj1 AB)).
Qed.

Lemma aligned_add_le x y A: aligned (x + y) A ->
  pad x A <= y mod A /\ pad y A <= x mod A.
Proof.
  assert (H: forall x y, aligned (x + y) A -> pad x A <= y mod A). {
    intros x' y' XYP.
    pose (Anz := proj1 XYP).
    unfold pad.
    case_eq (x' mod A); [ intro H; apply Nat.le_0_l|].
    intros n XA.
    pose (H := aligned_mod XYP).
    rewrite <- (Nat.add_mod_idemp_l x' _ _ Anz) in H.
    rewrite <- (Nat.add_mod_idemp_r _ y' _ Anz) in H.
    destruct (proj1 (Nat.mod_divides _ _ Anz) H) as [k K].
    refine (proj2 (Nat.le_sub_le_add_r _ _ _) _).
    rewrite Nat.add_comm, <- XA, K.
    rewrite <- (Nat.mul_1_r _) at 1.
    refine (Nat.mul_le_mono_l _ _ _ _).
    case (Nat.le_gt_cases 1 k); [auto|].
    intro K1.
    rewrite (proj1 (Nat.lt_1_r _) K1), Nat.mul_0_r in K.
    now rewrite (proj1 (proj1 (Nat.eq_add_0 _ _) K)) in XA.
  }

  intro K; split; [| rewrite Nat.add_comm in K]; exact (H _ _ K).
Qed.

Axiom accessible : nat -> Prop.
Definition accessible_range b n := forall m, m < n -> accessible (b + m).
Definition mmap P := forall n, { p | aligned p P /\ accessible_range p n }.

Record Allocation (n A P: nat) := mkAllocation {
  data: nat;
  data_alignment: aligned data A;
  data_accessible: accessible_range data n;
}.

Lemma naive_allocator {P} (M: mmap P):
  forall n {A}, aligned P A -> Allocation n A P.
Proof.
  intros n A PA.
  destruct (M n) as [x [XP XAcc]].
  pose (Anz := proj1 PA).
  refine (mkAllocation _ _ _ x _ _); unfold aligned, pad.
  + now rewrite (aligned_mod (align_weaken _ PA XP)).
  + exact XAcc.
Qed.

Record GuardedAllocation (n A P: nat) := mkGuardedAllocation {
  allocation: Allocation n A P;

  mmapper: mmap P;
  mmapped_size: nat;
  base := proj1_sig (mmapper mmapped_size);

  offset: nat;
  data' := data _ _ _ allocation;
  pad_pre: nat;
  data_offset: data' = base + offset + P + pad_pre;
  pre_guard: aligned (base + offset) P;
  post_guard: offset + P + pad_pre + n + pad (data' + n) P + P <= mmapped_size;
}.

Lemma naive_guarded_allocator {P} (M: mmap P):
  forall n {A}, aligned P A -> GuardedAllocation n A P.
Proof.
  intros n A PA.
  pose (N := P + n + pad n P + P).
  case_eq (M N); intros x [XP XAcc] Mx.
  pose (Anz := proj1 PA).
  pose (Pnz := proj1 XP).

  assert (da: aligned (x + P) A). {
    unfold aligned.
    now rewrite (pad_add_l _ _ _ Anz (aligned_mod (align_weaken _ PA XP))).
  }

  assert (dacc: accessible_range (x + P) n). {
    intros i I.
    rewrite <- Nat.add_assoc.
    refine (XAcc _ _).
    lia.
  }

  refine (mkGuardedAllocation _ _ _ (mkAllocation _ _ _ (x + P) da dacc) M N 0 0 _ _ _).
  + rewrite Mx. simpl. lia.
  + rewrite Mx. simpl.
    unfold aligned.
    now rewrite (pad_add_l _ _ _ Pnz (aligned_mod XP)), (pad_0 Pnz).
  + simpl.
    repeat rewrite <- Nat.add_assoc.
    rewrite (pad_add_l _ _ _ Pnz (aligned_mod XP)).
    rewrite (pad_add_l _ _ _ Pnz (Nat.mod_same _ Pnz)).
    lia.
Qed.

Record OptimalAllocation (n A P: nat) := mkOptimalAllocation {
  guarded_allocation: GuardedAllocation n A P;
  post_padding_min: forall a': GuardedAllocation n A P,
    pad (data' _ _ _ guarded_allocation + n) P <= pad (data' _ _ _ a' + n) P;
  mmapped_size_min: forall a': GuardedAllocation n A P,
    mmapped_size _ _ _ guarded_allocation <= mmapped_size _ _ _ a';
}.

Lemma optimal_allocation_min_pad_pre {n A P} (a: OptimalAllocation n A P):
  forall a': GuardedAllocation n A P,
  pad_pre _ _ _ (guarded_allocation _ _ _ a) <= pad_pre _ _ _ a'.
Admitted.

Lemma optimal_allocator_page_aligned {P} (M: mmap P):
  forall n {A}, aligned P A -> OptimalAllocation n A P.
Proof.
  intros n A PA.

  pose (N := P + n + pad n P + P).
  case_eq (M N). intros x [XP XAcc] Mx.

  pose (Anz := proj1 PA).
  pose (Pnz := proj1 XP).
  pose (XA := aligned_mod (align_weaken x PA XP)).

  pose (k := pad (x + P) A / P).
  pose (p0 := pad (x + P) A mod P).
  pose (pi i := p0 + i * A).
  pose (di i := x + (1 + k) * P + pi i).
  pose (qi i := pad (di i + n) P).

  assert (P0: p0 = 0). {
    unfold p0.
    now rewrite (pad_add_l _ _ _ Anz XA), (proj2 PA), (Nat.mod_0_l _ Pnz).
  }

  assert (K0: k = 0). {
    unfold k.
    rewrite (pad_add_l _ _ _ Anz XA), (proj2 PA).
    now apply Nat.div_0_l.
  }

  pose (i := pad_minimizer A n P).

  simple refine (mkOptimalAllocation _ _ _ (mkGuardedAllocation _ _ _ (mkAllocation n A P (di i) _ _) M N 0 (pi i) _ _ _) _ _).
  - refine (conj Anz _).
    unfold di, pi.
    rewrite K0, P0, Nat.add_0_r, Nat.add_0_l, Nat.mul_1_l.
    repeat rewrite <- Nat.add_assoc.
    rewrite (pad_add_l _ _ _ Anz XA).
    rewrite (pad_add_l _ _ _ Anz (aligned_mod PA)).
    unfold pad.
    now rewrite (Nat.mod_mul _ _ Anz).
  - intros j J.
    unfold di, pi.
    rewrite K0, P0, Nat.add_0_r, Nat.add_0_l, Nat.mul_1_l.
    repeat rewrite <- Nat.add_assoc.
    refine (XAcc _ _).
    unfold N.
    repeat rewrite <- Nat.add_assoc.
    refine (proj1 (Nat.add_lt_mono_l _ _ _) _).
    rewrite Nat.add_comm.
    refine (Nat.add_lt_le_mono _ _ _ _ J _).
    rewrite <- Nat.add_0_l at 1.
    refine (Nat.add_le_mono _ _ _ _ (Nat.le_0_l _) _).
    refine (Nat.le_trans (i * A) (P / A * A) P _ _).
    + unfold i; exact (Nat.mul_le_mono_r _ _ A (pad_minimizer_bound A n P Anz)).
    + rewrite Nat.mul_comm; now apply Nat.mul_div_le.
  - rewrite Mx.
    unfold di, pi.
    simpl.
    repeat rewrite <- Nat.add_assoc.
    rewrite P0, K0, Nat.mul_0_l.
    now repeat rewrite Nat.add_0_l.
  - rewrite Mx.
    now rewrite Nat.add_0_r.
  - simpl.
    unfold di, pi, N.
    rewrite K0, P0, Nat.add_0_r, Nat.add_0_l, Nat.mul_1_l.
    repeat rewrite <- Nat.add_assoc.
    rewrite (pad_add_l _ _ _ Pnz (aligned_mod XP)).
    rewrite (pad_add_l _ _ _ Pnz (Nat.mod_same _ Pnz)).
    refine (proj1 (Nat.add_le_mono_l _ _ _) _).
    repeat rewrite Nat.add_assoc.
    refine (proj1 (Nat.add_le_mono_r _ _ _) _).
    case (Nat.eq_dec (n mod P) 0).
    + intro z.
      unfold i, pad_minimizer.
      rewrite (proj2 (Nat.eqb_eq _ _) z).
      now rewrite Nat.mul_0_l, Nat.add_0_l.
    + intro nz.
      rewrite <- Nat.add_assoc.
      rewrite Nat.add_comm.
      rewrite <- Nat.add_assoc.
      refine (proj1 (Nat.add_le_mono_l _ _ _) _).
      rewrite Nat.add_comm.
      rewrite (pad_add_small _ _ _ Pnz); [auto|].
      admit. (* i * A < pad n P *)
  - intro a'.
    unfold data'.
    simpl.
    unfold di, pi.
    rewrite K0, P0, Nat.add_0_r, Nat.add_0_l, Nat.mul_1_l.
    repeat rewrite <- Nat.add_assoc.
    rewrite (pad_add_l _ _ _ Pnz (aligned_mod XP)).
    rewrite (pad_add_l _ _ _ Pnz (Nat.mod_same _ Pnz)).
    destruct (proj1 (Nat.mod_divides _ _ Anz) (aligned_mod (data_alignment _ _ _ (allocation _ _ _ a')))) as [j J].
    rewrite J, Nat.mul_comm.
    apply (pad_min _ _ _ (aligned_mod PA)).
  - intro a'. simpl.
    unfold N.
    refine (Nat.le_trans _ _ _ _ (post_guard _ _ _ a')).
    refine (proj1 (Nat.add_le_mono_r _ _ _) _).
    repeat rewrite <- Nat.add_assoc.
    rewrite <- Nat.add_0_l at 1.
    refine (Nat.add_le_mono _ _ _ _ (Nat.le_0_l _) _).
    refine (proj1 (Nat.add_le_mono_l _ _ _) _).

    rewrite <- (Nat.add_comm _ (pad_pre n A P a')).
    rewrite <- Nat.add_assoc.
    refine (proj1 (Nat.add_le_mono_l _ _ _) _).

    rewrite (data_offset _ _ _ a').
    rewrite <- Nat.add_assoc at 1.
    rewrite <- Nat.add_assoc at 1.
    rewrite (pad_add_l _ _ P Pnz (aligned_mod (pre_guard _ _ _ a'))).
    rewrite (pad_add_l _ _ P Pnz (Nat.mod_same _ Pnz)).
    rewrite Nat.add_comm.

    rewrite (Nat.div_mod (pad_pre n A P a') P Pnz).
    rewrite <- Nat.add_0_l at 1.
    rewrite <- Nat.add_assoc.
    refine (Nat.add_le_mono _ _ _ _ (Nat.le_0_l _) _).
    rewrite <- Nat.add_assoc.
    rewrite (pad_add_l _ _ _ Pnz); [|now rewrite Nat.mul_comm, Nat.mod_mul].
    rewrite (pad_add_small _ _ _ Pnz); [auto|].
    admit. (* pad_pre n A P a' mod P < pad n P *)
Admitted.
