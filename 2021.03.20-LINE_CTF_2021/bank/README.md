# bank (mini writeup)

* A menu-based console app for managing users, bank accounts and playing a
  lottery.
* Bug: the lottery uses the glibc RNG.
* Take a loan, buy a ticket, predict all the winning numbers and win the
  biggest prize.
* Bug: entering the name and the address after winning the biggest prize allows
  leaking the binary address as well as the libc address.
* Repay the loan in 20 installments (this will create 20 history entries).
* Having a lot of money, no debt and a long history grants access to the VIP
  transfer functionality. VIP transfers are different from the regular
  transfers in that they use the callback function, whose address is located
  after the user's memo field.
* Bug: obtaining the VIP status increases the memo length limit, but not the
  actual length.
* Edit the memo and overwrite the callback with the one_gadget address.
* Make a VIP transfer in a way that the arguments are 0s in order to satisfy
  the one_gadget's constraints.
