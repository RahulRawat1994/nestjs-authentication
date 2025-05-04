import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  JoinTable,
} from 'typeorm';
import { Session } from './session.entity';
import { VerificationToken } from './verification_token.entity';
import { SocialAccount } from './social_account.entity';
import { Role } from './role.entity';
@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', length: 50, unique: true, nullable: false })
  username: string;

  @Column({ type: 'varchar', length: 100, unique: true, nullable: false })
  email: string;

  @Column({ type: 'text', nullable: true })
  password_hash: string;

  @Column({ nullable: true })
  avatar: string;

  @Column({ default: true })
  is_active: boolean;

  @Column({ default: false })
  is_verified: boolean;

  @OneToMany(() => Session, (session) => session.user)
  sessions: Session[];

  // One-to-many relation with social accounts (see next section)
  @OneToMany(() => SocialAccount, (social) => social.user)
  socialAccounts: SocialAccount[];

  @OneToMany(() => VerificationToken, (token) => token.user)
  verification_tokens: VerificationToken[];

  @JoinTable()
  roles: Role[];

  @CreateDateColumn({ type: 'timestamp' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp' })
  updated_at: Date;

  @Column({ type: 'timestamp', nullable: true })
  deleted_at: Date;
}
