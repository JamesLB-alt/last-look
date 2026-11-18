use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
}
