Require Import Arith.
Require Import NArith.
Require Import Vector.
Require Import List.
Require Import Ascii.
Require Import String.

Inductive Brainfuck : Type :=
  | Incr : Brainfuck
  | Decr : Brainfuck
  | Next : Brainfuck
  | Prev : Brainfuck
  | Read : Brainfuck
  | Write : Brainfuck
  | While : list Brainfuck -> Brainfuck.

Definition byte := ascii.

Function byte_succ (n : byte) := ascii_of_N (N.succ (N_of_ascii n)).
Function byte_pred (n : byte) := ascii_of_N (N.add 255 (N_of_ascii n)).

Theorem byte_pred_0 : byte_pred "000"%char = "255"%char.
Proof.
  compute.
  trivial.
Qed.

Theorem byte_succ_255 : byte_succ "255"%char = "000"%char.
Proof.
  compute.
  trivial.
Qed.

Theorem byte_succ_pred : forall n : byte, byte_succ (byte_pred n) = n.
Proof.
  intro n.
  destruct n.
  destruct b, b0, b1, b2, b3, b4, b5, b6.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
  trivial. trivial. trivial. trivial. trivial. trivial. trivial. trivial.
Qed.

Definition Len : nat := 3000. (* a little small to define functions with quickly *)
(* memory, pointer, input, output *)
Inductive State : Type :=
  | Memory : Vector.t byte Len -> Fin.t Len -> string -> string -> State.

Function state_update_memory (s : State) (f : Vector.t byte Len -> Fin.t Len -> Vector.t byte Len) : State :=
  match s with
  | Memory mem ptr input output => Memory (f mem ptr) ptr input output
  end.

Function state_incr (s : State) : State :=
  state_update_memory s (fun mem ptr => replace mem ptr (byte_succ (Vector.nth mem ptr))).

Function state_decr (s : State) : State :=
  state_update_memory s (fun mem ptr => replace mem ptr (byte_pred (Vector.nth mem ptr))).

Function state_update_pointer (s : State) (f : Vector.t byte Len -> Fin.t Len -> option (Fin.t Len)) : option State :=
  match s with
  | Memory mem ptr input output =>
    option_map (fun ptr' => Memory mem ptr' input output) (f mem ptr)
  end.

Function state_next (s : State) : option State :=
  state_update_pointer s (fun mem ptr =>
    match lt_dec (S (proj1_sig (Fin.to_nat ptr))) Len with
    | left  p => Some (Fin.of_nat_lt p : Fin.t Len)
    | right _ => None
    end).

Function state_prev (s : State) : option State :=
  state_update_pointer s (fun mem ptr =>
    match Fin.to_nat ptr with
    | exist i p =>
      match zerop i with
      | left  _ => None
      | right q => Some (Fin.of_nat_lt (lt_trans (Peano.pred i) i Len (lt_pred_n_n i q) p) : Fin.t Len)
      end
    end).

Function state_read (s : State) : option State :=
  match s with
  | Memory mem ptr (String c cs) output =>
    Some (Memory (replace mem ptr c) ptr cs output)
  | _ => None
  end.

(* accumurate output in the reversed order *)
Function state_write (s : State) : State :=
  match s with
  | Memory mem ptr input output =>
    Memory mem ptr input (String (Vector.nth mem ptr) output)
  end.

Function byte_zerob (n : byte) : bool :=
  match n with
  | Ascii false false false false false false false false => true
  | _ => false
  end.

Function state_zerob (s : State) : bool :=
  match s with
  | Memory mem ptr _ _ => byte_zerob (Vector.nth mem ptr)
  end.

Inductive EvalResult : Type :=
  | Success
  | Interrupted
  | LeftIndexExceeded
  | RightIndexExceeded
  | EndOfInput.

Fixpoint eval (n : nat) (s : State) (tss : list (list Brainfuck)) : EvalResult * nat * State * list (list Brainfuck) :=
  let failure e := (e, n, s, tss) in
  match n with
  | O => failure Interrupted
  | S n' =>
    match tss with
    | nil => failure Success
    | nil :: tss' => eval n' s tss'
    | (t :: ts) :: tss' =>
      let success s' := eval n' s' (ts :: tss') in
      let try x e :=
        match x with
        | None => failure e
        | Some s' => success s'
        end in
      match t with
      | Incr => success (state_incr s)
      | Decr => success (state_decr s)
      | Next => try (state_next s) RightIndexExceeded
      | Prev => try (state_prev s)  LeftIndexExceeded
      | Read => try (state_read s) EndOfInput
      | Write => success (state_write s)
      | While ts' => eval n' s (if state_zerob s then ts :: tss' else ts' :: tss)
      end
    end
  end.

Fixpoint string_rev (s : string) : string :=
  match s with
  | EmptyString => EmptyString
  | String c s' => append (string_rev s') (String c EmptyString)
  end.

Function execute' (n : nat) (code : list Brainfuck) (input : string)
    : EvalResult * nat * State * list (list Brainfuck) :=
  eval n (Memory (Vector.const zero Len) Fin.F1 input EmptyString) (code :: nil).

Function execute (n : nat) (code : list Brainfuck) (input : string) : option string :=
  match execute' n code input with
  | (Success, _, Memory _ _ _ output, nil) => Some (string_rev output)
  | _ => None
  end.

Definition option_bind { A B : Type } (f : option A) (g : (A -> option B)) :=
  match f with
  | None => None
  | Some f' => g f'
  end.

Fixpoint drop (n : nat) (s : string) :=
  match n with
  | O => s
  | S n' => match s with
    | EmptyString => s
    | String _ s' => drop n' s'
    end
  end.

Fixpoint parse' (code : string) (top : list Brainfuck) (stack : list (list Brainfuck)) : option (list Brainfuck) :=
  match code with
  | EmptyString =>
    match stack with
    | nil => Some top
    | _ => None
    end
  | String "+" code' => parse' code' (top ++ Incr  :: nil) stack
  | String "-" code' => parse' code' (top ++ Decr  :: nil) stack
  | String ">" code' => parse' code' (top ++ Next  :: nil) stack
  | String "<" code' => parse' code' (top ++ Prev  :: nil) stack
  | String "," code' => parse' code' (top ++ Read  :: nil) stack
  | String "." code' => parse' code' (top ++ Write :: nil) stack
  | String "[" code' => parse' code' nil (top :: stack)
  | String "]" code' =>
    match stack with
    | nil => None
    | x :: xs => parse' code' (x ++ While top :: nil) xs
    end
  | String _ code' => parse' code' top stack
  end.

Fixpoint parse (code : string) : option (list Brainfuck) := parse' code nil nil.
Function execute_string (n : nat) (code : string) (input : string) : option string := option_bind (parse code) (fun code => execute n code input).

Definition A_code := "++++++++[>++++++++<-]>+."%string.
Theorem test_A : execute_string 1000 A_code EmptyString = Some "A"%string.
Proof.
  compute.
  trivial.
Qed.

(* http://pc11.2ch.net/test/read.cgi/tech/1036013915/197 *)
Definition helloworld_code := "++++[>++++[>++++>++++++>++<<<-]>++>+<<<-]>>.>+.+++++++..+++.>.<<-<++++[>++++<-]>.>.+++.------.--------.>+."%string.
Theorem test_helloworld : execute_string 10000 helloworld_code EmptyString = Some "Hello World!"%string.
Proof.
  compute.
  trivial.
Qed.