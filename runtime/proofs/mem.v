Require Import PeanoNat.

Definition pad x N :=
  match x mod N with 0 => 0 | r => N - r end.

Definition aligned x N := N <> 0 /\ pad x N = 0.

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

Lemma round_left_cancel {N a} b: aligned a (S N) -> pad (a + b) (S N) = pad b (S N).
Proof.
  intro A.
  unfold pad.
  rewrite <- (Nat.add_mod_idemp_l a b _ (proj1 A)).
  now rewrite (aligned_mod A), Nat.add_0_l.
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

  pad_pre: nat;
  pad_pre_prop: pad_pre < data;
  page_alignment_pre: aligned (data - pad_pre) P;
  pad_post: nat;
  page_alignment_post: aligned (data + n + pad_post) P;
}.

Lemma naive_allocator {P} (M: mmap P):
  forall n {A}, aligned P A -> Allocation n A P.
Proof.
  intros n A PA.
  destruct (M (P + n)) as [x [XP XAcc]].
  pose (Anz := proj1 PA).
  pose (Pnz := proj1 XP).
  refine (mkAllocation _ _ _ (x + P) _ _ _ _ _ _ _).
  + unfold aligned, pad.
    split. auto.
    rewrite <- (Nat.add_mod_idemp_l x P A Anz).
    destruct (proj1 (Nat.mod_divides x P Pnz) (aligned_mod XP)) as [i I].
    destruct (proj1 (Nat.mod_divides P A Anz) (aligned_mod PA)) as [j J].
    rewrite I, J, <- Nat.mul_assoc, Nat.mul_comm, Nat.mod_mul by auto.
    now rewrite Nat.add_0_l, Nat.mul_comm, Nat.mod_mul by auto.
  + intros i I.
    rewrite <- Nat.add_assoc.
    refine (XAcc _ _).
    exact (proj1 (Nat.add_lt_mono_l _ _ _) I).
  + now refine (Nat.add_le_lt_mono _ _ _ _ (Nat.le_0_l _) (proj1 (Nat.neq_0_lt_0 _) _)).
  + rewrite Nat.sub_0_r.
    unfold aligned, pad.
    rewrite <- (Nat.add_mod_idemp_l _ _ _ Pnz).
    rewrite (aligned_mod XP), Nat.add_0_l.
    now rewrite Nat.mod_same.
  + now apply aligned_add_pad.
Qed.

Definition OptimalAllocation (n A P: nat) :=
  let A := Allocation n A P in
  exists a: A, forall a': A, pad_post _ _ _ a <= pad_post _ _ _ a'.
(* TODO: optimize over pre as well *)

Lemma optimal_allocator_page_aligned {P} (M: mmap P):
  forall n {A}, aligned P A -> OptimalAllocation n A P.
Proof.
  intros n A PA.
  pose (Anz := proj1 PA).

  pose (N := P + n).

  destruct (M N) as [x [XP XAcc]].
  pose (Pnz := proj1 XP).
  pose (k := pad (x + P) A / P).
  pose (p0 := pad (x + P) A mod P).
  pose (pi i := p0 + i * A).
  pose (di i := x + (1 + k) * P + pi i).
  pose (qi i := pad (di i + n) P).

  assert (XA: x mod A = 0). {
    destruct (proj1 (Nat.mod_divides x P Pnz) (aligned_mod XP)) as [i I].
    destruct (proj1 (Nat.mod_divides P A Anz) (aligned_mod PA)) as [j J].
    rewrite I, J.
    rewrite <- Nat.mul_assoc, Nat.mul_comm.
    now apply Nat.mod_mul.
  }

  assert (XPA: (x + P) mod A = 0). {
    rewrite <- (Nat.add_mod_idemp_l x P A Anz), XA.
    now apply aligned_mod.
  }

  assert (P0: p0 = 0). {
    unfold p0 in *.
    unfold pad.
    rewrite XPA.
    now apply Nat.mod_0_l.
  }

  destruct (proj1 (Nat.mod_divides P A Anz) (aligned_mod PA)) as [j J].

  assert (Qi: forall i,
    qi i = match (A * i + n mod (A * j)) mod (A * j) with 0 => 0 | S n => A * j - S n end
  ). {
    intro i. unfold qi, di, pad, pi.
    rewrite J in *.
    rewrite <- Nat.add_assoc, <- Nat.add_assoc.
    rewrite <- (Nat.add_mod_idemp_l x _ _ Pnz).
    rewrite (aligned_mod XP), Nat.add_0_l.
    rewrite P0, Nat.add_0_l.
    rewrite <- (Nat.add_mod_idemp_l _ _ _ Pnz).
    rewrite (Nat.mod_mul _ _ Pnz), Nat.add_0_l.
    rewrite <- (Nat.add_mod_idemp_r _ _ _ Pnz).
    now rewrite Nat.mul_comm.
  }
Admitted.
